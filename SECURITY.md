# Security Policy / 安全策略

## Reporting a vulnerability / 报告漏洞

**Please do not open a public issue for a security problem.**

> **安全问题请不要开公开 issue。**

Because this is a shell extension, the highest-impact class of bug is not memory
corruption in the usual sense — it is anything that can **crash `explorer.exe`**
or let a crafted file influence the host. Please report privately first so a fix
can ship before the details do.

> 因为这是 shell 扩展，影响最大的一类问题不是通常意义上的内存破坏，而是任何能**搞崩
> `explorer.exe`**、或让构造的文件影响到宿主进程的问题。请先私下报告，让修复先于细节
> 公开。

Report through the repository's **private vulnerability reporting** (the *Security*
tab → *Report a vulnerability*). If that is unavailable, contact the maintainer by
the address on the repository's commit history.

> 请通过仓库的**私密漏洞报告**（*Security* 标签页 → *Report a vulnerability*）提交。
> 若不可用，请用仓库提交历史中的维护者邮箱联系。

Please include, as far as you can:

> 请尽量包含：

- What the issue is, and whether it affects the extension, the CLI, or both.
- Steps to reproduce, and the Windows version and architecture.
- Whether the process crashed, hung, or merely misbehaved — and if it crashed,
  whether the host (`explorer.exe`) went down with it.

> - 问题是什么，影响的是扩展、命令行，还是两者。
> - 复现步骤，以及 Windows 版本与架构。
> - 进程是崩溃、卡死，还是仅仅行为异常；如果是崩溃，宿主（`explorer.exe`）是否一起挂了。

## Scope / 范围

In scope: the shell extension, its property sheet page and context menu entry, the
hash algorithms, checksum-file parsing, and the installer.

> 范围内：shell 扩展、其属性页与右键菜单项、哈希算法、校验和文件解析，以及安装器。

Out of scope: vulnerabilities in third-party crates (report those upstream, though
we will bump a dependency promptly), and anything requiring an attacker to already
have administrator rights or code execution on the machine.

> 范围外：第三方 crate 的漏洞（请向上游报告，但我们会尽快升级依赖），以及需要攻击者
> 已经拥有管理员权限或本机代码执行能力的问题。

## What this project will not do / 本项目不会做的事

Two things users sometimes ask for, which are refused on principle:

> 用户有时会要求、但出于原则拒绝的两件事：

- **Send a file's contents anywhere.** The optional reputation lookup sends a
  digest, never file data, and it is off until the user explicitly accepts the
  remote service's terms.
- **Write outside its own directories.** Settings live in `HKCU\Software\rustHashTab`,
  and the extension does not modify the files it hashes.

> - **把文件内容发到任何地方。** 可选的哈希信誉查询只发送摘要，从不发送文件数据，且在
>   用户明确接受远端服务条款之前一直关闭。
> - **写入自身目录之外的位置。** 设置存放在 `HKCU\Software\rustHashTab`，扩展不会修改
>   它所哈希的文件。
