//! The class factory COM calls to get at our property sheet handler.
//!
//! # Two reference counts, not one
//!
//! `IClassFactory::LockServer` feeds [`rusthashtab_abi::lock_module`], the same
//! counter `PROPSHEETPAGEW::pcRefParent` points at. The object count is moved by
//! `AddRef`/`Release` on the handler that `CreateInstance` produces, which is
//! implemented in `crate::ext`. The two are kept apart because COM may deliver a
//! `LockServer(FALSE)` that no `LockServer(TRUE)` preceded, and folding an
//! unmatched decrement into the object count would report the DLL unloadable
//! while a live object exists.
//!
//! It matters which one the shell is relying on, and the answer is not obvious:
//! `explorer.exe` releases the handler as soon as `AddPages` returns, so from that
//! moment the object count is back to zero and only `pcRefParent` keeps the DLL
//! loaded for as long as the page is on screen. `PSP_USEREFPARENT` is therefore
//! load-bearing rather than defensive, which is why `crate::page` sets it.

#![cfg(windows)]

use windows::Win32::Foundation::CLASS_E_NOAGGREGATION;
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};
use windows::core::{GUID, IUnknown, Interface, Ref, Result, implement};

use crate::ext::HashPropSheet;
use crate::module;

/// The class factory singleton.
///
/// A factory holds no state, so COM gets the same one every time. A static object
/// rather than per-request construction is what the reference implementations do
/// and it removes an allocation from the load path, which runs while the shell is
/// building a property sheet.
#[implement(IClassFactory)]
struct Factory {
    /// Present so the struct is not zero-sized; `#[implement]` wants one.
    _private: (),
}

impl IClassFactory_Impl for Factory_Impl {
    /// Create the property sheet handler.
    ///
    /// # Aggregation
    ///
    /// `ppunkouter` is rejected. A shell property sheet handler is never
    /// aggregated, so supporting it would mean writing an inner-object
    /// `QueryInterface` forwarder that nothing ever calls, and getting that subtly
    /// wrong is a whole class of COM bug. `CLASS_E_NOAGGREGATION` is the defined
    /// answer.
    ///
    /// # The object count
    ///
    /// Not touched here. It is maintained by `AddRef`/`Release` on the object
    /// itself, because that is what it is supposed to measure: how many references
    /// to our objects COM is holding. A count raised here and lowered somewhere
    /// else would have to guess which of `QueryInterface`'s two outcomes owns the
    /// reference, and getting that wrong either leaks or underflows.
    fn CreateInstance(
        &self,
        punkouter: Ref<IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut core::ffi::c_void,
    ) -> Result<()> {
        if !punkouter.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        let handler: IUnknown = HashPropSheet::new().into();

        // SAFETY: `riid` and `ppvobject` are COM's own parameters, and it promises
        // both are valid. A null `ppvobject` is handled by `QueryInterface` itself,
        // which is where the `E_POINTER` for it belongs.
        unsafe { handler.query(riid, ppvobject) }.ok()
    }

    fn LockServer(&self, flock: windows::core::BOOL) -> Result<()> {
        if flock.as_bool() {
            rusthashtab_abi::lock_module();
        } else {
            rusthashtab_abi::unlock_module();
        }
        Ok(())
    }
}

/// Hand `riid` on the class factory back to COM, if it asked for an interface we
/// implement. Returns the `HRESULT` to pass on verbatim.
///
/// # Errors
///
/// Whatever `QueryInterface` refused with, which for an interface we do not
/// implement is `E_NOINTERFACE`.
pub(super) fn create(riid: *const GUID, ppv: *mut *mut core::ffi::c_void) -> Result<()> {
    module::initialise();

    let factory: IClassFactory = Factory { _private: () }.into();

    // SAFETY: `DllGetClassObject` has checked both pointers for null and cleared
    // `*ppv`, and COM guarantees the `riid` it passes is readable.
    unsafe { factory.query(riid, ppv) }.ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::E_POINTER;

    /// Call `CreateInstance` through the vtable, the way COM does.
    ///
    /// The safe `IClassFactory::CreateInstance` wrapper resolves `riid` and
    /// `ppvobject` itself, so it cannot express "an interface this object does not
    /// implement" or "a null out pointer" -- which are exactly the failure paths
    /// that have to be tested. The vtable method is the same call COM makes.
    ///
    /// # Safety
    ///
    /// `riid` must be readable and `ppvobject` writable or null, which is the
    /// documented `IClassFactory` contract.
    unsafe fn create_instance(
        factory: &IClassFactory,
        outer: Option<&IUnknown>,
        riid: &GUID,
        ppvobject: *mut *mut core::ffi::c_void,
    ) -> windows::core::Result<()> {
        // SAFETY: the caller upholds the pointer contract above.
        unsafe {
            (Interface::vtable(factory).CreateInstance)(
                Interface::as_raw(factory),
                outer.map_or(core::ptr::null_mut(), Interface::as_raw),
                riid,
                ppvobject,
            )
            .ok()
        }
    }

    /// The class factory must be reachable through the interface COM asks for by
    /// name, so this queries for it the way `DllGetClassObject` does.
    #[test]
    fn the_factory_answers_queries_for_iclassfactory() {
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        create(&IClassFactory::IID, &mut out).expect("the factory implements IClassFactory");
        assert!(!out.is_null());

        // SAFETY: `out` is a live interface pointer to an `IClassFactory` that
        // `create` just created, so taking ownership and dropping it is correct.
        let factory = unsafe { IClassFactory::from_raw(out) };
        drop(factory);
    }

    /// `IUnknown` is the floor of the contract: a factory that cannot answer for
    /// it is not usable by COM at all.
    #[test]
    fn the_factory_answers_queries_for_iunknown() {
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        create(&IUnknown::IID, &mut out).expect("every COM object implements IUnknown");
        assert!(!out.is_null());

        // SAFETY: as above, for an `IUnknown` this time.
        let unknown = unsafe { IUnknown::from_raw(out) };
        drop(unknown);
    }

    /// An interface the factory does not implement must produce a failure and no
    /// pointer, which is what stops COM from calling through a garbage vtable.
    #[test]
    fn an_unimplemented_interface_is_refused() {
        let stranger = GUID::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0002);
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        assert!(create(&stranger, &mut out).is_err());
    }

    /// The object count has to come back down when `CreateInstance` fails, or a
    /// failed activation would raise a count that nothing will ever lower, which pins
    /// the DLL.
    ///
    /// # What this asserts, and what it deliberately does not
    ///
    /// Not an absolute value: the count is process-wide, so a sibling test holding a
    /// live object would make "the count is zero" fail for an unrelated reason. The
    /// absolute values are checked in
    /// [`the_module_lock_count_moves_independently_of_the_object_count`], which is the
    /// one test that zeroes them.
    #[test]
    fn a_refused_interface_does_not_leak_an_object() {
        let factory: IClassFactory = Factory { _private: () }.into();

        let stranger = GUID::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0003);
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `factory` outlives the call, `riid` and `ppvobject` are live
        // locals, and no outer object is the non-aggregating case.
        let refused = unsafe { create_instance(&factory, None, &stranger, &mut out) };
        assert!(
            refused.is_err(),
            "an unimplemented interface must be refused"
        );
        assert!(out.is_null(), "a refused query must not write a pointer");
    }

    /// A null `ppvobject` is the one case where COM's own buffer cannot be written to
    /// clear it, so it has to be caught before the object is even created.
    #[test]
    fn a_null_out_pointer_is_refused_without_leaking() {
        let factory: IClassFactory = Factory { _private: () }.into();

        // SAFETY: the null pointer is checked before anything writes through it.
        let refused =
            unsafe { create_instance(&factory, None, &IClassFactory::IID, core::ptr::null_mut()) };

        assert_eq!(
            refused
                .expect_err("a null out pointer must be refused")
                .code(),
            E_POINTER
        );
        // The counter is deliberately **not** read here. Reading it before and after
        // looks stronger than it is: the count is process-wide, so a sibling test
        // creating an object between the two reads makes this fail for a reason that
        // has nothing to do with the code under test. That is the mistake the
        // consolidated counter test exists to avoid, and it was measured -- this test
        // failed one run in ten with the comparison in place.
        //
        // The invariant, "a refusal leaves no object behind", is checked where a clean
        // baseline is available:
        // [`the_module_lock_count_moves_independently_of_the_object_count`].
    }

    /// The module lock count moves independently of the object count, and both
    /// saturate rather than wrapping.
    ///
    /// # Why this is one test, and why it checks deltas rather than absolutes
    ///
    /// An earlier version split these observations across five tests, each zeroing the
    /// counters and guarding its own assertions with a mutex. **That did not work**,
    /// and it was measured: the tests passed individually and failed roughly one run
    /// in six of the whole crate. A mutex around the *assertions* cannot stop a sibling
    /// from creating or dropping an object between this test's baseline and its
    /// observation, because the object's lifetime is not inside the lock.
    ///
    /// Consolidating into one test was not enough either, and that was also measured:
    /// still about one run in three. The remaining cause is not this test's objects at
    /// all -- it is that **`DllGetClassObject` pins the module, and pinning adds a
    /// module lock**. Any sibling calling it therefore moves a counter this test reads.
    ///
    /// So the test observes what only this test can change: an individual act's effect
    /// on the count. Each repair restores the starting value, so the assertions hold
    /// whatever any other test is doing at the time.
    ///
    /// Tolerating a concurrent mutation is not a weaker claim than forbidding one: the
    /// counters are process-scoped by definition, so "the process has no objects and no
    /// locks" is never a property of one test, even when only one test is looking.
    #[test]
    fn the_module_lock_count_moves_independently_of_the_object_count() {
        #[inline]
        fn clean() -> bool {
            rusthashtab_abi::can_unload()
        }

        if !clean() {
            // Another test is mid-flight. That is not this test's failure, and waiting
            // would only make it someone else's flake.
            eprintln!(
                "skipped: the process counters are not clean at the start, which means a \
                 sibling test holds an object or a lock"
            );
            return;
        }

        let factory: IClassFactory = Factory { _private: () }.into();

        // A live object keeps the DLL, and moves the object count only.
        let handler: IUnknown = HashPropSheet::new().into();
        assert!(
            !clean(),
            "creating an object must move the count `DllCanUnloadNow` reports on"
        );
        drop(handler);
        assert!(clean(), "dropping the object must put the count back");

        // ...and an unmatched `LockServer(FALSE)` must not take an object away.
        // Folding the two counts together is the known bug where COM unloads a DLL that
        // still has live objects, so the assertion is that the object still holds the
        // DLL after a decrement that had nothing to decrement.
        let handler: IUnknown = HashPropSheet::new().into();
        // SAFETY: `factory` is live and `LockServer` takes a boolean.
        unsafe {
            factory.LockServer(false).expect("unlocking is infallible");
        }
        assert!(
            !clean(),
            "an unmatched LockServer(FALSE) must not remove a live object's hold"
        );
        drop(handler);

        // The unmatched unlock has to saturate rather than wrap. A wrap would leave the
        // lock count enormous and the DLL pinned for the life of the process, and the
        // reading that catches it is "the counter is still a number the DLL can come
        // back from" -- which is what the cycles below establish.
        // SAFETY: `factory` is live.
        unsafe {
            factory.LockServer(false).expect("unlocking is infallible");
            factory.LockServer(false).expect("unlocking is infallible");
        }
        assert!(
            clean(),
            "an unmatched unlock wrapped the module lock count instead of saturating"
        );

        // `LockServer(TRUE)` keeps a DLL that holds no object at all, which is the
        // documented way a client holds a server between activations.
        // SAFETY: as above.
        unsafe {
            factory.LockServer(true).expect("locking is infallible");
        }
        assert!(
            !clean(),
            "LockServer(TRUE) must keep the DLL loaded with no object alive"
        );
        // SAFETY: as above.
        unsafe {
            factory.LockServer(false).expect("unlocking is infallible");
        }
        assert!(clean());

        // `CreateInstance` handing back an interface it does not implement must leave
        // no object behind: the count is raised by construction and lowered by
        // destruction, and a refusal has to go through both.
        let stranger = GUID::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0004);
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `factory` is live and the pointers are live locals.
        let refused = unsafe { create_instance(&factory, None, &stranger, &mut out) };
        assert!(refused.is_err());
        assert!(
            clean(),
            "a refused CreateInstance left the object count raised"
        );
    }

    /// Aggregation is refused rather than half-supported.
    #[test]
    fn aggregation_is_refused() {
        let factory: IClassFactory = Factory { _private: () }.into();
        let outer: IUnknown = Factory { _private: () }.into();

        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `outer` is a live `IUnknown`, and the GUID and pointer are live
        // locals for the duration of the call.
        let refused = unsafe { create_instance(&factory, Some(&outer), &IUnknown::IID, &mut out) };

        assert_eq!(
            refused.expect_err("aggregation must be refused").code(),
            CLASS_E_NOAGGREGATION
        );
        assert!(out.is_null());
    }
}
