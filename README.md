# rustHashTab

A Windows shell extension that calculates and verifies file hashes, right from the
file Properties dialog.

> 一个 Windows shell 扩展：直接在文件「属性」对话框中计算和校验文件哈希。

Select any file, open **Properties**, and the **Hashes** tab shows its digest under
every algorithm you have enabled — computed in parallel, with a running progress bar.
Paste a hash you were given and it is highlighted green or red as it matches. There is
also a right-click context menu entry and a standalone mode for when you just want a
hash quickly.

> 选中任意文件打开**属性**，**Hashes** 标签页会列出所有已启用算法下的摘要——并行计算，
> 并带实时进度条。粘贴别人给你的哈希值，匹配与否会直接标色。此外还有右键菜单项，
> 以及只想要一个哈希值时的独立运行模式。

> **Bilingual document.** Every section is written in English first, then Chinese.
> English is authoritative; if the two disagree, English wins. **When you change one
> language, update the other in the same commit.**
>
> **本文档为中英双语。** 每节先英文、后中文。以英文为准；两者若有出入，以英文为准。
> **改动一种语言时，必须在同一次提交中同步另一种。**

> **Status: pre-alpha.** All 31 hash algorithms are implemented and externally verified;
> the shell extension, UI and installer are being built. See [Roadmap](#roadmap--路线图).
>
> **状态：pre-alpha。** 全部 31 种哈希算法已实现并通过外部校验；shell 扩展、界面与安装器
> 正在开发中。见[路线图](#roadmap--路线图)。

---

## Features / 功能

- **31 hash algorithms** in one pass over the file (see [Algorithms](#algorithms--算法))
- **Parallel hashing** — every enabled algorithm runs over each block concurrently
- **Verification** — paste a digest, or point it at a checksum file; matches are
  coloured green (secure) or amber (weak) against a red mismatch
- **Checksum file support** — reads and writes `sha256sum`-style files, SFV, and corz `.hash`
- **Reputation lookup** — optional, opt-in, off by default
- **Native look** — a real Win32 dialog, DPI-aware, no bundled toolkit
- **35 languages** for the interface
- **Multi-architecture** — x86, x64 and ARM64
- **Long path support**
- **One DLL per architecture** — CPU feature dispatch happens at runtime, so there is
  no per-ISA binary to choose between

**中文**

- **一次遍历计算 31 种哈希算法**（见[算法](#algorithms--算法)）
- **并行哈希** —— 每个启用的算法并发处理同一个数据块
- **校验** —— 粘贴一段哈希，或指向校验和文件；匹配按绿（安全算法）或琥珀（弱算法）标色，
  不匹配标红
- **校验和文件支持** —— 读写 `sha256sum` 风格文件、SFV 以及 corz `.hash`
- **信誉查询** —— 可选、需显式同意、默认关闭
- **原生外观** —— 真正的 Win32 对话框，支持 DPI 缩放，不捆绑任何 GUI 工具包
- **界面支持 35 种语言**
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
  rusthashtab-net        reputation lookup and update check
  rusthashtab-ui         Win32 dialog UI
xtask/                   developer automation: verification, benchmarks, pre-commit gate
docs/internal/           design notes and research -- NOT shipped / 不随发行物发布
```

Each crate has one job. The shell-extension DLL is thin: it implements COM, creates the
property sheet page, and delegates everything else.

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

Also verified:

> 另外还有：

- **Streaming is a tested invariant.** Every algorithm must produce the same digest whether
  data arrives in one call, in 2 MiB blocks, or one byte at a time. The scanner feeds 2 MiB
  blocks, so a chunk-size-dependent digest would be a silent corruption bug.
- **ParallelHash128/256** are checked against the independent XKCP C reference
  implementation at multiple block sizes, including empty input, plus a second differential
  test against an unrelated Rust implementation.

> - **流式是受测试保护的不变式。** 无论数据是一次性喂入、按 2 MiB 分块喂入，还是逐字节
>   喂入，每个算法都必须产出相同摘要。扫描器正是按 2 MiB 分块读取的，所以分块相关的摘要
>   就是一个静默的数据损坏 bug。
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

### Phase 2 — the scan pipeline / 扫描管线

Async reads, a bounded pool of 2 MiB buffers (1 GiB ceiling), cancellation, and
per-file progress reporting.

> 异步读取、有界的 2 MiB 缓冲池（上限 1 GiB）、可取消、逐文件进度上报。

**Gate / 门禁:** `cargo xtask check`. New invariant under test: feeding a file in 2 MiB
blocks must produce the same digest as feeding it whole, for **all 31** algorithms.
Correctness here is the algorithm layer's, already proven; what is new is the pipeline, so
the test is that the pipeline does not change the answer.

> 新增受测不变式：对**全部 31 个**算法，按 2 MiB 分块喂入与整体喂入必须产出相同摘要。
> 正确性本身属于算法层、已经证明过；这里新的是管线，所以测的是"管线不改变答案"。

### Phase 3 — the property sheet page / 属性页

`IShellExtInit` + `IShellPropSheetExt`, the results list, DPI awareness.

> `IShellExtInit` + `IShellPropSheetExt`、结果列表、DPI 适配。

**Gate / 门禁:** `cargo xtask check`, plus a manual check that the page renders inside the
real `explorer.exe` Properties dialog. The COM invariants documented for contributors are
what this phase is actually about.

> `cargo xtask check`，外加在真实 `explorer.exe` 属性对话框中人工确认渲染正常。这个阶段真正
> 的重点是贡献者文档里那几条 COM 不变式。

### Phase 4 — checksum files and settings / 校验和文件与设置

Wire `rusthashtab-sumfile` and `rusthashtab-settings` into the UI: read a checksum file,
verify against it, export in every supported format.

> 把 `rusthashtab-sumfile` 与 `rusthashtab-settings` 接进界面：读取校验和文件、据此校验、
> 按所有支持格式导出。

**Gate / 门禁:** `cargo xtask check`. The parser's correctness is checked against real
checksum files produced by `sha256sum`, `openssl dgst` and `7z`, not against fixtures this
repository authored.

> `cargo xtask check`。解析器的正确性对照的是 `sha256sum`、`openssl dgst`、`7z` 真实产出的
> 校验和文件，而不是本仓库自己造的样例。

### Phase 5 — context menu, localization, standalone mode / 右键菜单、本地化、独立模式

`IContextMenu`, the 35-language resource pipeline, standalone mode and file associations.

> `IContextMenu`、35 种语言的资源管线、独立模式与文件关联。

**Gate / 门禁:** `cargo xtask check` + the release-hygiene job.

### Phase 6 — release / 发布

Installer (per-user and per-machine MSI × x86/x64/ARM64), Authenticode signing, the
false-positive workflow.

> 安装器（每用户/每机器 MSI × x86/x64/ARM64）、Authenticode 签名、误报处理流程。

**Gate / 门禁:** `cargo xtask check` on all three target triples, plus the release-hygiene
job: no internal research in any artifact, every README section still bilingual, no upstream
identifier in any shipped file.

> 三个目标三元组上跑 `cargo xtask check`，外加发布卫生作业：任何产物中都不含内部资料、README
> 每一节仍然双语、任何随发行发布的文件都不含上游标识符。

### Status / 当前进度

| Phase | State / 状态 |
|---|---|
| Workspace, CI matrix, licence, verification harness / 工作区、CI 矩阵、许可证、校验工具 | ✅ done |
| Phase 1 algorithms — 31 of 31 verified / 第一阶段算法 —— 31 个全部已验证 | ✅ done / 已完成 |
| Phases 2–6 | ⬜ not started / 未开始 |

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

