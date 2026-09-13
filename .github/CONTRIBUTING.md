# Contributing / 贡献指南

Thanks for taking a look. This file is short on purpose; the details that matter
are enforced by tooling rather than described here.

> 感谢关注。本文刻意写得很短——真正重要的规矩由工具强制执行，而不是靠文档描述。

## Getting set up / 搭建环境

See [Building](../README.md#building--构建) in the README. Short version:

> 见 README 的[构建](../README.md#building--构建)一节。简短版：

```powershell
cargo xtask check     # everything that must pass before a commit
```

That is the whole workflow. `cargo xtask check` runs formatting, clippy with
`-D warnings`, the test suite, the algorithm coverage audit, byte-for-byte
verification against OpenSSL, and repository hygiene checks. If it passes, the
change is in the shape this project expects.

> 这就是全部流程。`cargo xtask check` 会跑格式检查、带 `-D warnings` 的 clippy、
> 测试、算法覆盖审计、与 OpenSSL 的逐字节校验，以及仓库卫生检查。它过了，改动就符合
> 本项目的期望形态。

## Correctness / 正确性

A digest compared only against a constant this repository also produced proves
nothing — it cannot catch a mistake that was there from the start. So every
algorithm must agree with an authority **outside** this repository:

> 一个只跟本仓库自己产生的常量吻合的摘要什么也证明不了——它抓不到"从一开始就抄错了"的
> 错误。因此每个算法都必须与**本仓库之外**的权威一致：

```powershell
cargo xtask audit     # which algorithm is validated by what
cargo xtask verify    # run the checks against OpenSSL
```

`cargo xtask audit` fails if any algorithm has no authority attached. Do not
attach a plausible-sounding source to make it pass — the value of that map is
that the gaps are visible.

> `cargo xtask audit` 会在某个算法没有权威时失败。**不要为了让检查通过而填一个听起来
> 合理的来源**——那张覆盖图的价值恰恰在于缺口是可见的。

## Adding an algorithm / 新增算法

1. Implement it behind the `Hasher` trait in `rusthashtab-hash`.
2. Register it with its exact digest length.
3. Attach an external authority in `xtask/src/coverage.rs`.
4. Add a reference-vector test, with a comment naming where the vector came from.
5. Confirm chunking invariance — the digest must be identical whether data arrives
   in one call, in 2 MiB blocks, or byte by byte. The scanner reads 2 MiB blocks, so
   a chunk-size-dependent digest would be silent corruption.
6. Run `cargo xtask check`.

> 1. 在 `rusthashtab-hash` 中以 `Hasher` trait 实现它。
> 2. 按精确的摘要长度注册。
> 3. 在 `xtask/src/coverage.rs` 里挂上外部权威。
> 4. 加参考向量测试，注释里写明向量来源。
> 5. 确认分块不变性——无论一次性喂入、按 2 MiB 分块还是逐字节喂入，摘要必须一致。
>    扫描器按 2 MiB 分块读取，所以分块相关的摘要就是静默数据损坏。
> 6. 跑 `cargo xtask check`。

## Please do not submit / 请不要提交

- **Code copied from another project.** Implementation comes from specifications
  and published test vectors. This project is a clean-room implementation and the
  provenance rules are not negotiable.
- **Generated or vendored third-party source.** Use a dependency.
- **A digest with a test that only checks it against a value this repository
  produced.** See *Correctness* above.

> - **从别的项目抄来的代码。** 实现来自规范与公开测试向量。本项目是 clean-room 实现，
>   来源规则不可协商。
> - **生成或内联的第三方源码。** 请使用依赖。
> - **只跟本仓库自产的值比对的摘要测试。** 见上面的「正确性」。

## Reporting a security issue / 报告安全问题

Please do not open a public issue. See [SECURITY.md](../SECURITY.md).

> 请不要开公开 issue。见 [SECURITY.md](../SECURITY.md)。
