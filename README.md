# rustHashTab

A Windows shell extension that calculates and verifies file hashes, right from the
file Properties dialog.

> 一个 Windows shell 扩展：直接在文件「属性」对话框中计算和校验文件哈希。

Select any file, open **Properties**, and the **Hashes** tab shows its digest under
every algorithm you have enabled — with a running progress bar. Paste a hash you were
given and it is highlighted green or red as it matches. The context menu, standalone
mode, localization and installer are planned; see [Roadmap](#roadmap--路线图).

> 选中任意文件打开**属性**，**Hashes** 标签页会列出所有已启用算法下的摘要，
> 并带实时进度条。粘贴别人给你的哈希值，匹配与否会直接标色。右键菜单、独立运行模式、
> 本地化与安装器仍在路线图中，见[路线图](#roadmap--路线图)。

> **Bilingual document.** Every section is written in English first, then Chinese.
> English is authoritative; if the two disagree, English wins. **When you change one
> language, update the other in the same commit.**
>
> **本文档为中英双语。** 每节先英文、后中文。以英文为准；两者若有出入，以英文为准。
> **改动一种语言时，必须在同一次提交中同步另一种。**

> **Status: alpha.** All 31 hash algorithms are implemented and externally verified, the
> scan pipeline is done, and the Shell Properties page now verifies against pasted digests
> and checksum files, exports them in every supported format, and has a settings dialog.
> The context menu, localization, standalone mode and the installer are still to come.
> See [Roadmap](#roadmap--路线图).
>
> **状态：alpha。** 全部 31 种哈希算法已实现并通过外部校验，扫描管线已完成；Shell 属性页
> 现在支持用粘贴的摘要或校验和文件进行校验、按所有支持格式导出，并有设置对话框。
> 右键菜单、本地化、独立模式与安装器仍待开发。见[路线图](#roadmap--路线图)。

---

## Features / 功能

- **31 hash algorithms** in one pass over the file (see [Algorithms](#algorithms--算法))
- **Parallel hashing** — files are hashed concurrently; each block is fed to every
  enabled algorithm
- **Verification** — paste a digest, or point it at a checksum file; matches are
  coloured green (secure) or amber (weak) against a red mismatch
- **Checksum file support** — reads and writes `sha256sum`-style files, SFV, and corz `.hash`
- **Native look** — a real Win32 dialog, DPI-aware, no bundled toolkit
- **Multi-architecture** — x86, x64 and ARM64
- **Long path support**
- **One DLL per architecture** — CPU feature dispatch happens at runtime, so there is
  no per-ISA binary to choose between

**中文**

- **一次遍历计算 31 种哈希算法**（见[算法](#algorithms--算法)）
- **并行哈希** —— 文件并发哈希；每个数据块依次喂给所有已启用算法
- **校验** —— 粘贴一段哈希，或指向校验和文件；匹配按绿（安全算法）或琥珀（弱算法）标色，
  不匹配标红
- **校验和文件支持** —— 读写 `sha256sum` 风格文件、SFV 以及 corz `.hash`
- **原生外观** —— 真正的 Win32 对话框，支持 DPI 缩放，不捆绑任何 GUI 工具包
- **多架构** —— x86、x64 与 ARM64
- **长路径支持**
- **每个架构只有一个 DLL** —— CPU 特性派发在运行时完成，不存在需要挑选的按指令集拆分的二进制

## Algorithms / 算法

| Group / 分组 | Algorithms / 算法 |
|---|---|
| Checksums / 校验和 | CRC32, CRC64 (XZ) |
| Non-cryptographic / 非加密 | XXH32, XXH64, XXH3-64, XXH3-128, QuickXorHash, eD2k, eD2k (Old) |
| Legacy / 旧式 | MD4, MD5, RIPEMD-160, SHA-1 |
| SHA-2 | SHA-224, SHA-256, SHA-384, SHA-512 |
| SHA-3 | SHA3-224, SHA3-256, SHA3-384, SHA3-512 |
| BLAKE | BLAKE2sp, BLAKE3 (256), BLAKE3 (512) |
| Keccak / SP 800-185 | KangarooTwelve (264, 256, 512), ParallelHash128 (264), ParallelHash256 (528) |
| Russian standard / 俄罗斯标准 | GOST R 34.11-2012 / Streebog (256, 512) |

Only four are enabled by default — MD5, SHA-1, SHA-256 and SHA-512 — because hashing a
large file under all 31 at once is measurably slower and almost nobody needs GOST and
KangarooTwelve at the same time. Turn on whatever you need in Settings.

> 默认只启用四种——MD5、SHA-1、SHA-256 和 SHA-512——因为对大文件同时算满 31 种会明显变慢，
> 而几乎没有人需要同时用上 GOST 和 KangarooTwelve。按需在设置里打开即可。

## Install / 安装

Not yet available. When it is, there will be per-user and per-machine MSI packages for
each architecture.

> 暂未提供。发布后将按架构分别提供「每用户」与「每机器」两种 MSI 安装包。

## Building / 构建

### Prerequisites / 前置条件

| Requirement / 需求 | Notes / 说明 |
|---|---|
| Rust | **1.98.1** or newer (`rust-toolchain.toml` pins it; `rustup` fetches it) / **1.98.1** 或更新（`rust-toolchain.toml` 已钉版本，`rustup` 会自动拉取） |
| Visual Studio 2022 | The **C++ build tools** workload — `rustc` locates the Windows SDK itself, so no Developer Command Prompt is needed / 需勾选 **C++ 生成工具**工作负载——`rustc` 会自行定位 Windows SDK，**不需要**开发者命令提示符 |
| Targets / 目标平台 | `rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc aarch64-pc-windows-msvc` |
| Verification tools / 校验工具 | `openssl` 3.x and `sha256sum` (from Git for Windows) for `cargo xtask verify --require-tools`; 7-Zip is optional and only supplies CRC32 values / `cargo xtask verify --require-tools` 需要 `openssl` 3.x 与 `sha256sum`（Git for Windows 自带）；7-Zip 可选，只用于提供 CRC32 数值 |

**Do not use Rust 1.98.0.** It miscompiles trait-object vtables — it can emit a null function
pointer where a real one belongs ([rust-lang/rust#161441](https://github.com/rust-lang/rust/issues/161441),
fixed in 1.98.1). A shell extension is nothing but vtables.

> **不要用 Rust 1.98.0。** 它会错误编译 trait 对象虚表——本应放函数指针的位置可能被写成
> 空指针（[rust-lang/rust#161441](https://github.com/rust-lang/rust/issues/161441)，
> 已在 1.98.1 修复）。而 shell 扩展就是一堆虚表。

### Commands / 命令

```powershell
cargo xtask check     # everything that must pass before a commit
cargo build --release --target x86_64-pc-windows-msvc
cargo test  --workspace --target x86_64-pc-windows-msvc
cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo fmt --all
```

Pass `--target` explicitly. Without it cargo builds for the **host**, which on a machine whose
`rustup` default host is GNU means the MinGW build rather than the MSVC one that ships — a
green test run then says nothing about the artifact users get.

> 请显式传 `--target`。不传时 cargo 构建的是 **host**；如果某台机器 `rustup` 的默认 host
> 是 GNU，那测的就是 MinGW 构建而不是发布用的 MSVC 构建——测试全绿却对用户拿到的产物
> 什么都没证明。

`cargo xtask check` covers all three supported targets, not just one. It lints each of them and
runs the test suite wherever the resulting binaries can actually execute on the current machine:
`x86_64` and `i686` binaries run natively on an x64 Windows host, while `aarch64` is compiled and
linked but not run. A single-target gate is how a 64-bit-only constant once passed every local
check and still failed to compile for 32-bit.

> `cargo xtask check` **覆盖全部三个受支持 target**，而不只是一个。它逐个 lint，并在当前机器
> 真能执行二进制时跑测试：`x86_64` 与 `i686` 在 x64 Windows host 上原生运行，`aarch64`
> 只编译并链接、不运行。只查一个 target 的门禁，曾让一个仅 64 位成立的常量通过了所有本地
> 检查，却在 32 位下根本编译不过。

### Toolchain

**Windows builds use MSVC only.** `x86_64-pc-windows-msvc` is the one supported configuration;
`rust-toolchain.toml` pins only MSVC targets, and CI builds only MSVC.

The reason is not the ABI — the x86_64 C ABI is compatible and cross-loading works in both
directions. It is that a GNU-built DLL **carries no PDB**, so a debugger attached inside
`explorer.exe` can show only disassembly. For a shell extension, whose failure mode is crashing
the user's desktop, that is the wrong trade. The GNU target is also officially unmaintained,
its linker does not understand the MSVC flags this project needs (`/DELAYLOAD:` has no
equivalent), and its CRT dependency varies with whichever MinGW is on `PATH` — so the same
source produces a different dependency set on different machines.

> ### 工具链
>
> **Windows 构建只用 MSVC。** `x86_64-pc-windows-msvc` 是唯一受支持的配置；
> `rust-toolchain.toml` 只钉 MSVC 目标，CI 也只构建 MSVC。
>
> 理由**不是** ABI——x86_64 的 C ABI 是兼容的，跨加载双向实测可用。真正的理由是：
> GNU 构建的 DLL **不带 PDB**，所以在 `explorer.exe` 里附加调试器只能看反汇编。
> 对一个"故障模式是搞崩用户桌面"的 shell 扩展来说，这个代价划不来。此外该目标官方
> 声明无人维护；它的链接器看不懂本项目需要的 MSVC 参数（`/DELAYLOAD:` 没有等价物）；
> 而且它的 CRT 依赖随 `PATH` 上的 MinGW 口味变化——同一份源码在不同机器上会链接出
> 不同的依赖集。

The hash crate exposes internal state for diagnostics under a non-default feature. It is
for tests only and must never be enabled in a release build:

> 哈希 crate 在一个非默认 feature 下暴露内部状态用于诊断。它仅供测试使用，
> **绝不能**在发行构建中启用：

```powershell
cargo test -p rusthashtab-hash --features test-internals
```

## Project layout / 项目结构

```
crates/
  rusthashtab-abi        COM plumbing, HRESULT conversion, panic containment
  rusthashtab-hash       the 31 algorithms, as uniform streaming contexts
  rusthashtab-sumfile    checksum file parsing and export
  rusthashtab-settings   persisted user settings
  rusthashtab-scan       file discovery and the concurrent hashing pipeline
  rusthashtab-net        reputation/update scaffolding, not wired into the UI yet
  rusthashtab-ui         Win32 dialog UI and the property sheet page
  rusthashtab-shell      the shell extension DLL: COM plumbing and registration
xtask/                   developer automation: verification, benchmarks, pre-commit gate
docs/internal/           design notes and research -- NOT shipped / 不随发行物发布
```

Each crate has one job. The shell-extension DLL is thin: it implements COM, registers
itself, and delegates everything else to `rusthashtab-ui`, which is an ordinary library
and can therefore be tested by an ordinary test binary.

> 每个 crate 只负责一件事。shell 扩展 DLL 本身很薄：它只实现 COM、完成注册，其余全部
> 委派给 `rusthashtab-ui`——那是一个普通库，因此可以用普通的测试二进制来测。

> 每个 crate 只负责一件事。shell 扩展 DLL 本身很薄：它只实现 COM、创建属性页，其余全部
> 委派出去。

## Correctness / 正确性

A hash is either exactly right or worthless, and a digest that only agrees with a constant
this repository also produced proves nothing — it cannot catch a mistake that was there
from the start. So correctness rests on **independent authorities**:

> 哈希要么完全正确，要么毫无价值。而一个只跟本仓库自己产生的常量吻合的摘要什么也证明不了
> ——它抓不到"从一开始就抄错了"的错误。因此正确性建立在**独立权威**之上：

| Authority / 权威 | Covers / 覆盖 |
|---|---|
| OpenSSL 3.x | SHA-1, SHA-2 ×4, SHA-3 ×4, MD5, RIPEMD-160 |
| Published standard vectors / 公开标准向量 | MD4 (RFC 1320) |
| Vendored upstream vector files / 上游向量文件（vendored） | BLAKE3, BLAKE2sp, KangarooTwelve, GOST (gost-engine etalon), QuickXorHash (rclone) |
| Upstream reference implementations / 上游参考实现 | xxHash, ParallelHash (XKCP), eD2k |
| CRC catalogue check values / CRC 目录校验值 | CRC32, CRC64/XZ |
| Real checksum files produced by other tools / 其他工具真实产出的校验和文件 | `sha256sum`, `openssl dgst` (parsing), `sha256sum -c` (our export), `7z` (SFV CRC32 values) |

```powershell
cargo xtask check     # everything that must pass before a commit
cargo xtask verify    # byte-for-byte differential check against OpenSSL
cargo xtask audit     # which algorithm is validated by what
cargo xtask bench     # throughput
```

`cargo xtask verify` currently performs **698 byte-for-byte comparisons**: 264 against
OpenSSL across 24 payload sizes chosen to land on block and padding boundaries (including
exactly 2 MiB, the scanner's read block), plus 434 against vector files vendored from
upstream authorities under `vectors/`. In CI it fails the build if OpenSSL is missing
rather than silently checking nothing.

> `cargo xtask verify` 目前执行 **698 次逐字节比对**：其中 264 次对照 OpenSSL，覆盖 24 种
> 刻意落在分块与填充边界上的载荷长度（包括恰好 2 MiB——扫描器的读取块大小）；另外 434
> 次对照 `vectors/` 下从上游权威 vendored 的向量文件。CI 中 OpenSSL 缺失时它会让构建
> 失败，而不是静默地什么都不检查。

It then crosses the checksum-file layer with the same tools: real files written by
`sha256sum` and `openssl dgst` must parse to the digests the algorithms compute,
`sha256sum -c` must accept the file our exporter writes, and the CRC32 values in our
SFV export are compared against `7z h -scrcCRC32`. corz `.hash` has no external producer,
so for it the check is export→parse round-tripping, and the output says so rather than
pretending otherwise.

> 随后它用同一批工具交叉检查校验和文件层：`sha256sum` 与 `openssl dgst` 写出的真实文件
> 必须解析出算法算出的摘要；我们导出的 `.sha256` 必须能通过 `sha256sum -c`；我们导出的
> SFV 里的 CRC32 数值要与 `7z h -scrcCRC32` 比对。corz `.hash` 没有外部生产者，所以对它
> 的检查是导出→解析往返，输出里会如实说明，而不是假装已经交叉验证。

Also verified:

> 另外还有：

- **Streaming is a tested invariant.** Every algorithm must produce the same digest whether
  data arrives in one call, in 2 MiB blocks, or one byte at a time. The scanner feeds 2 MiB
  blocks, so a chunk-size-dependent digest would be a silent corruption bug.
- **The pipeline does not change the answer.** Every digest a scan produces is compared, for
  **all 31 algorithms**, against the same algorithm fed the whole file in one call — at sizes
  that land exactly on a block boundary, where a read-ahead ring that dropped, duplicated or
  reordered a block would show up.
- **ParallelHash128/256** are checked against the independent XKCP C reference
  implementation at multiple block sizes, including empty input, plus a second differential
  test against an unrelated Rust implementation.

> - **流式是受测试保护的不变式。** 无论数据是一次性喂入、按 2 MiB 分块喂入，还是逐字节
>   喂入，每个算法都必须产出相同摘要。扫描器正是按 2 MiB 分块读取的，所以分块相关的摘要
>   就是一个静默的数据损坏 bug。
> - **管线不改变答案。** 扫描产出的每一个摘要，都会对**全部 31 种算法**与「一次性整体喂入」
>   的结果逐字节比对，并且专门覆盖恰好落在分块边界上的长度——读取预读环一旦丢块、重复块或
>   乱序，都会在这里暴露。
> - **ParallelHash128/256** 与独立的 XKCP C 参考实现在多个块大小上比对通过（含空输入），
>   另有第二个差分测试与一个不相关的 Rust 实现交叉验证。

Where a dependency disagrees with the specification, the specification wins and the
divergence is documented in the source — see `crates/rusthashtab-hash/src/parallel_hash.rs`
and `crates/rusthashtab-hash/src/quickxor.rs`.

> 当某个依赖与规范冲突时，以规范为准，并在源码中记录该分歧——见
> `crates/rusthashtab-hash/src/parallel_hash.rs` 与
> `crates/rusthashtab-hash/src/quickxor.rs`。

## Roadmap / 路线图

Every phase below ends with the same two gates, because neither is optional here:

> 下面每个阶段都以同样的两道门禁收尾，因为这两件事在这里都不是可选项：

1. **Code checks** — `cargo xtask check` (fmt, clippy with `-D warnings`, tests).
2. **External verification** — the phase's algorithms compared byte-for-byte against the
   authority named in the table, plus a benchmark run. Enforced in CI, and CI fails if the
   authority tool is missing rather than silently checking nothing.

> 1. **代码检查** —— `cargo xtask check`（fmt、clippy 带 `-D warnings`、测试）。
> 2. **外部校验** —— 本阶段的算法与表中指定的权威逐字节比对，外加一次基准测量。CI 会强制执行，
>    且权威工具缺失时 CI 直接失败，而不是静默地什么都不检查。

### Verification authorities / 校验权威

`xtask/src/coverage.rs` is the single source of truth. An algorithm cannot be marked done
without one.

> `xtask/src/coverage.rs` 是唯一事实来源。没有权威的算法不能标记为完成。

| Authority / 权威 | Cost / 成本 | Algorithms / 算法 |
|---|---|---|
| **OpenSSL 3.x** | free, widely installed | SHA-1, SHA-2 ×4, SHA-3 ×4, MD5, RIPEMD-160 |
| **Published standard vectors / 公开标准向量** | free, citable | MD4 (RFC 1320) |
| **Upstream reference implementation / vector files / 上游参考实现或向量文件** | needs a build or a vector file | BLAKE2sp, BLAKE3, KangarooTwelve, GOST (gost-engine etalon), ParallelHash (XKCP), eD2k, QuickXorHash (rclone) |

### Phase 1 — finish the algorithm set / 完成算法集 ✅

All 31 algorithms are implemented and verified. The sequencing below is the record of how
the coverage map closed — cheapest authority first, so it converged evenly instead of
leaving the awkward ones to the end.

> 全部 31 种算法已实现并通过校验。下面的顺序是覆盖图收敛过程的记录——权威最容易的先做，
> 因而均匀收敛，而不是把麻烦的留到最后。

| # | Algorithms | Authority | Extra work / 额外工作 |
|---|---|---|---|
| 1 | SHA3-224, SHA3-256, SHA3-384, SHA3-512 | OpenSSL `sha3-*` | none — pure `sha3` crate wiring / 无，纯接线 |
| 2 | BLAKE3, BLAKE3-512 | BLAKE3 `test_vectors.json` | extend `verify` to consume vector files / 让 `verify` 支持向量文件 |
| 3 | Blake2sp | BLAKE2 upstream `blake2sp.json` | same vector-file support / 同上 |
| 4 | K12-264, K12-256, K12-512 | KangarooTwelve draft vectors | decide KT128 (64-byte XOF read) vs KT256, then freeze a vector / 先确定 KT128 还是 KT256 |
| 5 | GOST 2012 (256), (512) | RFC 6986 §A.1 | none — `streebog` crate / 无 |
| 6 | eD2k, eD2k (Old) | eDonkey2000 spec | hand-write the ~120-line chunk tree over `md4`; must be checked at exactly 9,728,000 bytes / 手写分块树，必须测 9,728,000 边界 |
| 7 | QuickXorHash | Microsoft reference | none — `quickxorhash` crate / 无 |

**Gate / 门禁:** `cargo xtask audit` shows 31 verified, 0 pending; `cargo xtask verify`
passes with `--require-tools`; `cargo xtask bench` covers all 31.

**Status: complete — the gate above passes.** Two rows landed differently than planned:
GOST is verified against gost-engine's etalon suite (the tool ecosystem's byte order)
rather than RFC 6986's printed vectors, and QuickXorHash is our own implementation — the
`quickxorhash` crate produces non-standard digests on 32-bit targets.

> **状态：已完成——上述门禁已通过。** 有两行的落地方式与计划不同：GOST 对照的是
> gost-engine 的 etalon 套件（工具生态的字节序），而非 RFC 6986 的印刷向量；
> QuickXorHash 是我们的自研实现——`quickxorhash` crate 在 32 位目标上产出非标准摘要。

### Phase 2 — the scan pipeline / 扫描管线 ✅

Async reads, a bounded pool of 2 MiB buffers (1 GiB ceiling), cancellation, and
per-file progress reporting.

> 异步读取、有界的 2 MiB 缓冲池（上限 1 GiB）、可取消、逐文件进度上报。

**Gate / 门禁:** `cargo xtask check`. New invariant under test: feeding a file in 2 MiB
blocks must produce the same digest as feeding it whole, for **all 31** algorithms.
Correctness here is the algorithm layer's, already proven; what is new is the pipeline, so
the test is that the pipeline does not change the answer.

> 新增受测不变式：对**全部 31 个**算法，按 2 MiB 分块喂入与整体喂入必须产出相同摘要。
> 正确性本身属于算法层、已经证明过；这里新的是管线，所以测的是"管线不改变答案"。

**Status: complete — the gate above passes.** How the pipeline reads is worth stating
because it is where the difficulty was: each worker hashes one file at a time, issuing
several **overlapped** reads ahead of the block being hashed, so the device stays busy while
the CPU works. Buffers come from a pool shared by the whole scan and are recycled, so a
steady state allocates nothing per block, and a worker that cannot get a buffer reads *less
far ahead* rather than waiting for one — waiting is only ever done by a worker holding no
buffer at all, which is what makes a deadlock impossible. Cancelling cancels the I/O itself
and waits for every outstanding operation to be reaped before its buffer is released;
dropping the scan handle cancels and joins, so no thread outlives it.

> **状态：已完成——上述门禁已通过。** 管线的读取方式值得说明，因为难点正在这里：每个 worker
> 一次只处理一个文件，并在当前正在哈希的块之前发出若干**重叠（overlapped）**读，从而在 CPU
> 工作时让设备保持忙碌。缓冲来自整个扫描共享的池并循环复用，因此稳态下每块不产生任何分配；
> 拿不到缓冲的 worker 会**减少预读深度**，而不是等待缓冲——只有「一个缓冲都没持有」的 worker
> 才会等待，这正是死锁不可能发生的原因。取消会真正取消 I/O，并在释放缓冲之前等待每一个在飞
> 操作被收割；丢弃扫描句柄会取消并 join，因此没有任何线程会比扫描活得更久。

### Phase 3 — the property sheet page / 属性页 ✅

`IShellExtInit` + `IShellPropSheetExt`, the results list, DPI awareness.

> `IShellExtInit` + `IShellPropSheetExt`、结果列表、DPI 适配。

**Gate / 门禁:** `cargo xtask check`, plus a manual check that the page renders inside the
real `explorer.exe` Properties dialog. The COM invariants documented for contributors are
what this phase is actually about.

> `cargo xtask check`，外加在真实 `explorer.exe` 属性对话框中人工确认渲染正常。这个阶段真正
> 的重点是贡献者文档里那几条 COM 不变式。

**Status: done, and verified where it runs.** The page appears in a real file's
Properties dialog and hashes the selection there.

> **状态：已完成，并已在它真正运行的地方验收。** 页面会出现在真实文件的属性对话框里并哈希所选内容。

* The page hashes the selection, one row per enabled algorithm per file, and draws
  matched and mismatched rows in different colours. This is checked by hosting the page
  in a real dialog — `cargo test -p rusthashtab-ui --test property_sheet_page` opens it,
  reads the digest back out of the list view, and compares it with the algorithm's own
  output for the same bytes.
* Every COM invariant the contributors' notes call out has a test: panic containment at
  the vtable slot, `Agile = false`, independent and saturating lock and object counts,
  and no global thread pool.
* Registration is a real round trip against `HKCU` — register, read the values back,
  unregister, confirm they are gone — and it is per-user, so installing needs no
  elevation.
* **The dialog template is checked to be in the shipped DLL.**
  `the_dll_contains_the_pages_dialog_template` opens the built DLL as a data file and
  asserts `RT_DIALOG 101` is reachable through it. That check exists because the page
  was once invisible in `explorer.exe` while every other test passed: the template was
  compiled by a *library's* build script, and a `rustc-link-arg` from a library never
  reaches the `cdylib`, so the DLL shipped with no template and no page could be built
  from it. Asking "is it in the final artifact" is a different question from "is the
  code correct", and only the artifact is what a user sees.

> * 页面会哈希所选内容，每个文件×每个启用算法一行，匹配与不匹配行用不同颜色区分。这由「把页面
>   放进真实对话框」的测试覆盖——`cargo test -p rusthashtab-ui --test property_sheet_page`
>   会打开页面、从列表控件里读回摘要，并与算法对同一批字节的输出比对。
> * 贡献者文档点明的每一条 COM 不变式都有测试：vtable 槽位处的 panic 收容、`Agile = false`、
>   模块锁计数与对象计数彼此独立且饱和、不使用全局线程池。
> * 注册是**真实**的 `HKCU` 往返：注册、读回、注销、确认已删除。而且它是按用户的，
>   安装不需要提权。
> * **对话框模板「在不在发行 DLL 里」是被检查的。**
>   `the_dll_contains_the_pages_dialog_template` 把构建出的 DLL 当数据文件打开，
>   断言 `RT_DIALOG 101` 能从中取到。这条检查之所以存在，是因为页面曾经在
>   `explorer.exe` 里完全不可见、而其它所有测试都通过：模板由一个**库**的构建脚本编译，
>   而库发出的 `rustc-link-arg` 永远到不了 `cdylib`，于是 DLL 里没有模板，
>   也就永远建不出页面。「它在最终产物里吗」和「代码对不对」是两个不同的问题，
>   而用户能看到的只有最终产物。

### Phase 4 — checksum files, verification and settings / 校验和文件、校验与设置 ✅

The page verifies against a pasted digest or a checksum file — one the user picks, or one
found beside each hashed file when `LookForSumfiles` is on. Matches are coloured green
(secure), amber (weak) or red (mismatch), and the status line says where the verdicts came
from. Every supported format can be exported, and the settings dialog persists all 31
algorithm flags plus the display and export options.

> 属性页现在支持用粘贴的摘要或校验和文件校验——可以显式选择校验和文件，也可以在
> `LookForSumfiles` 打开时自动读取哈希文件旁边的那个。匹配按绿（安全算法）、琥珀（弱算法）
> 或红（不匹配）显示，状态行会写明判定来自哪个来源。所有支持格式都可导出，设置对话框会
> 持久化全部 31 个算法开关以及显示与导出选项。

**Gate / 门禁:** `cargo xtask check`, which includes the real-tool checksum-file
cross-check described under [Correctness](#correctness--正确性). As with Phase 3, a manual
pass in a real `explorer.exe` Properties dialog is the last step; the checklist and the
result are recorded in `docs/internal/PHASE4-CHECKSUM-AND-SETTINGS.md`.

> **门禁：** `cargo xtask check`，其中包含[正确性](#correctness--正确性)一节描述的真实
> 工具校验和文件交叉检查。与 Phase 3 一样，最后一步是在真实 `explorer.exe` 的属性对话框
> 里人工过一遍；清单与结果记录在 `docs/internal/PHASE4-CHECKSUM-AND-SETTINGS.md`。

**Status: complete and verified in a real Properties dialog.** The automated gate is green.
A manual pass on 2026-10-22 covered the default algorithm set, digests compared against an
independent tool, pasted-digest match/mismatch/non-hex handling, sidecar verification,
settings persistence, export to a checksum file verified with `md5sum -c`, copying a row,
and a clean close with `explorer.exe` still running.

> **状态：已完成，并已在真实属性对话框中验收。** 自动门禁全绿。2026-10-22 的人工验收覆盖了
> 默认算法集合、摘要与独立工具比对、粘贴摘要的正确/错误/非十六进制处理、sidecar 校验、
> 设置持久化、导出校验和文件并用 `md5sum -c` 复核、复制行，以及关闭属性对话框后
> `explorer.exe` 仍存活。

### Phase 5 — page completion and performance / 页面补全与性能

Sortable columns, copy interactions (double-click, context menu, `Ctrl+C`), cancel, stable
row order, DPI-correct column widths, configurable colours, a working monospace option, an
explicit export format selector with clipboard export, and clipboard-driven verification.
On the performance side: a combined-throughput benchmark, duplicate-path elimination,
single-file algorithm parallelism behind the scan's own threads, and better rendering for
large result sets.

> 结果列表排序、双击/右键/Ctrl+C 复制、取消、稳定行序、DPI 正确的列宽、可配置颜色、
> 真正生效的等宽字体、显式导出格式下拉与剪贴板导出、剪贴板驱动的校验。性能方面：
> 组合吞吐基准、重复路径去重、扫描自有线程上的单文件算法并行，以及大结果集的渲染改进。

**Status: done — the automated gate passes and the page is verified in a real
property sheet.** A manual visual pass in `explorer.exe` and the internal 150 MiB/s
all-algorithm target remain follow-ups recorded in the internal closure notes; they
do not change the feature set below. The page now sorts by any column, copies through double-click, the
context menu, `Ctrl+C` and the Copy button, cancels without blocking the dialog
thread, keeps rows in job order while results arrive, hides the File column for a
single file, paints five configurable row classes (with a high-contrast fallback),
exports an explicitly selected format to a file or the clipboard, and accepts a
bare hex/base64 digest or a whole GNU/SFV line for verification over all files or
the current one. On the performance side the scan chooses file-level or
algorithm-group scheduling from the file count, algorithm count and core count,
duplicate paths are removed before the 1000-file cap, and discovery reports
progress and can be cancelled.

> **状态：已完成——自动门禁通过，页面已在真实属性表中验证。** 真实 `explorer.exe` 的
> 人工视觉验收与内部 150 MiB/s 全算法目标仍作为后续事项记录在内部收口记录中，不影响下面的
> 功能范围。页面现在可按任意列
> 排序，支持双击、右键、`Ctrl+C` 与 Copy 按钮复制，取消不会阻塞对话框线程，结果到达时始终
> 按 job 序插入，单文件时隐藏 File 列，5 类行颜色可配置（高对比模式回退到系统色），
> 可显式选择导出格式并导出到文件或剪贴板，校验支持裸 hex/base64 或 GNU/SFV 整行，可作用于
> 全部文件或当前文件。性能方面，扫描按文件数、算法数与核数选择文件级或算法组级调度，
> 重复路径在 1000 文件上限之前去除，发现阶段有进度且可取消。

**Gate / 门禁:** `cargo xtask check`, `cargo xtask verify --require-tools`, real-control
page tests, and a recorded combined benchmark baseline.

> **门禁：** `cargo xtask check`、`cargo xtask verify --require-tools`、真实控件页面测试，
> 以及记录在案的组合吞吐基线。

### Phase 6 — workflows / 工作流

Interpret a selected checksum file as a manifest (hash the files it lists), infer the
algorithm from the file extension, make the verification scope explicit, tighten sidecar
matching, and finish the settings that affect those flows.

> 把选中的校验和文件当作清单解释（哈希其中列出的文件）、按扩展名推断算法、明确校验
> 作用范围、收紧 sidecar 匹配，并补全影响这些流程的设置项。

**Gate / 门禁:** `cargo xtask check` plus real-page tests for the manifest and verification
scope.

> **门禁：** `cargo xtask check`，外加清单模式与校验范围的真实页面测试。

### Phase 7 — context menu, standalone mode, file associations / 右键菜单、独立模式、文件关联

`IContextMenu`, a resizable windowed host that reuses the page, a standalone executable,
and associations for the checksum extensions we produce.

> `IContextMenu`、可缩放且复用属性页的独立窗口宿主、独立可执行文件，以及我们生成的
> 校验和扩展名关联。

**Gate / 门禁:** `cargo xtask check` plus a manual `explorer.exe` pass covering the menu,
standalone window, associations and closing the page cleanly.

> **门禁：** `cargo xtask check`，外加一次真实 `explorer.exe` 人工验收，覆盖右键菜单、
> 独立窗口、文件关联与关闭页面的清理。

### Phase 8 — localization and optional network features / 本地化与可选联网功能

A resource pipeline with language selection and fallback. English and Simplified Chinese
ship first; additional languages are added as translations are completed, and the README
only claims the languages that are actually finished. Reputation lookup and update checking
are out of scope for 1.0 unless a separate decision funds their key, terms and privacy work.

> 资源管线、语言选择与回退。先发布英文与简体中文；其余语言按翻译完成度逐步加入，
> README 只宣称实际完成的语言。信誉查询与更新检查不在 1.0 范围内，除非另做决定并为其
> key、条款与隐私工作投入资源。

**Gate / 门禁:** `cargo xtask check`; every language named in the README is present and
switchable, and no network request happens on a path that is documented as offline.

> **门禁：** `cargo xtask check`；README 声明的每种语言都存在且可切换，且文档说明为
> 离线的路径不会发出网络请求。

### Phase 9 — release / 发布

Installer (per-user and per-machine MSI × x86/x64/ARM64), Authenticode signing, the
false-positive workflow, a tested OS/architecture matrix, and release hygiene.

> 安装器（每用户/每机器 MSI × x86/x64/ARM64）、Authenticode 签名、误报处理流程、
> 经过测试的操作系统/架构矩阵，以及发布卫生。

**Gate / 门禁:** `cargo xtask check` on all three target triples, the release-hygiene job
(no internal research in any artifact, README still bilingual, no upstream identifier in a
shipped file), and an install→use→uninstall pass on a clean VM.

> **门禁：** 三个目标三元组上跑 `cargo xtask check`、发布卫生作业（任何产物中都不含内部
> 资料、README 每一节仍然双语、任何随发行发布的文件都不含上游标识符），以及在干净 VM 上
> 完成安装→使用→卸载。

### Status / 当前进度

| Phase | State / 状态 |
|---|---|
| Workspace, CI matrix, licence, verification harness / 工作区、CI 矩阵、许可证、校验工具 | ✅ done |
| Phase 1 algorithms — 31 of 31 verified / 第一阶段算法 —— 31 个全部已验证 | ✅ done / 已完成 |
| Phase 2 scan pipeline / 第二阶段扫描管线 | ✅ done / 已完成 |
| Phase 3 property sheet page / 第三阶段属性页 | ✅ done, verified in a real Properties dialog / 已完成，已在真实属性对话框中验收 |
| Phase 4 checksum files, verification and settings / 第四阶段 —— 校验和文件、校验与设置 | ✅ done, verified in a real Properties dialog / 已完成，已在真实属性对话框中验收 |
| Phase 5 page completion and performance / 第五阶段 —— 页面补全与性能 | ✅ done, automated gate green, verified in a real property sheet; explorer visual pass tracked as a follow-up / 已完成，自动门禁通过，已在真实属性表中验证；explorer 视觉验收作为后续事项跟踪 |
| Phase 6 workflows / 第六阶段 —— 工作流 | ⬜ not started / 未开始 |
| Phase 7 context menu, standalone mode, file associations / 第七阶段 —— 右键菜单、独立模式、文件关联 | ⬜ not started / 未开始 |
| Phase 8 localization and optional network features / 第八阶段 —— 本地化与可选联网 | ⬜ not started / 未开始 |
| Phase 9 release / 第九阶段 —— 发布 | ⬜ not started / 未开始 |

## Contributing / 贡献

The working rules — architecture, the invariants that must not be broken, and the
build/test workflow — are kept in the maintainers' internal notes. Contributors who need
them should ask. The short version: anything touching COM must not be able to take down
`explorer.exe`.

> 工作规则——架构、不可破坏的不变式、构建与测试流程——保存在维护者的内部笔记中。有需要的
> 贡献者请直接索取。简短版本是：任何触及 COM 的代码都不能把 `explorer.exe` 搞崩。

## License / 许可证

MIT. See [LICENSE-MIT](LICENSE-MIT).

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project by you shall be licensed under the MIT license, without any
additional terms or conditions.

> MIT 单一许可证。见 [LICENSE-MIT](LICENSE-MIT)。
>
> 除非你明确另行声明，任何有意提交以纳入本项目的贡献，均按 MIT 许可证授权，不附加任何
> 额外条款或条件。

### Third-party licences / 第三方许可证

This project links a number of Rust crates. All of them are permissively licensed and
none is copyleft, so the MIT licence above is compatible with every dependency.

> 本项目链接了若干 Rust crate。它们全部是宽松许可证，没有一个是 copyleft，因此上述 MIT
> 许可证与所有依赖都兼容。

| Crate / 依赖 | Licence / 许可证 |
|---|---|
| `sha2`, `sha1`, `sha3`, `md-5`, `md4`, `ripemd`, `streebog`, `digest`, `cshake`, `shake`, `k12` | MIT OR Apache-2.0 |
| `blake2s_simd`, `quickxorhash` | MIT |
| `crc32fast`, `crc` | MIT OR Apache-2.0 |
| `blake3` | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| `xxhash-rust` | BSL-1.0 |
| `windows`, `windows-core` | MIT OR Apache-2.0 |

`xxhash-rust` is Boost Software License 1.0 rather than the usual MIT/Apache pair — still
permissive and MIT-compatible, but worth naming because it is the odd one out and may trip
a naive licence scanner.

> `xxhash-rust` 用的是 Boost Software License 1.0，而不是常见的 MIT/Apache 双许可——同样
> 宽松、同样与 MIT 兼容，但因为它是唯一的例外、且可能触发粗糙的许可证扫描器，所以单独
> 列出来。

