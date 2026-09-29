# 验证代码修复是否真的生效

证明「修复前确实有漏洞、修复后确实修好」——拿证据，而不是「我看了一遍代码」。

## 技能清单

| 技能 | 说明 |
|---|---|
| **offline-fix-verify** · 修复验证 | 三层验证：框架桩（快速验证逻辑路径）→ 真实 HTTP（端到端请求）→ 完整闭环（全链路复现）。含「装不上依赖」时的降级手法（pip 失败怎么办）。 |

## 工作流

```
框架桩  →  真实 HTTP  →  完整闭环
（逻辑）    （请求）      （复现）
```

## 安装

把 `skills/` 下的技能目录拷贝到 WorkBuddy 的技能目录：

```bash
cp -r skills/* ~/.workbuddy/skills/
```

Windows PowerShell：

```powershell
Copy-Item .\skills\* "$env:USERPROFILE\.workbuddy\skills\" -Recurse -Force
```

重启 WorkBuddy 后，技能列表即可看到。

## 使用要点

- 适合场景：修了安全问题（路径穿越、SSRF、鉴权绕过）或并发问题（事件循环阻塞、竞态）之后。
- 触发词：验证修复、能不能跑通、验收、对照实验、漏洞验证、装不上依赖、pip 失败。

## 环境依赖

- Python 3.13

## 目录规范

```
offline-fix-verify/
└── skills/
    ├── offline-fix-verify/
```

每个技能遵循统一结构：`SKILL.md`（必需，含 name/description frontmatter）+ `scripts/`（可选）+ `references/`（可选）。

---

## License

MIT — 随意取用、修改、二次分发。
