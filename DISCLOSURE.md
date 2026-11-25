# 公开时间线

| 日期 | 事件 |
| --- | --- |
| 2021-02-11 | DedeCMS v5.8.1 release 发布 |
| 2021-11-22 | GitHub 出现 `MzzdToT/Dedecms5.8.1RCE`，公开「DedeCMS-5.8.1 SSTI模板注入RCE」PoC/EXP，入口 `/plus/recommend.php` |
| 2022-01-28 | `dedecms/DedeCMS` 官方仓库归档，之后无提交 |
| 2025-06-13 | GitHub 公开 CVE-2025-6335：dedeCMS 5.7 sp2 模板注入 RCE，入口 `/dede/co_get_corule.php` |
| 2026-11-25 | 本次审计：确认 v5.8.1 原包仍存在该链路，收敛到 `ShowMsg()`，枚举 58 处前台入口，定位过滤器赋值错误 |

行号以 `\n` 计数为准，与 GitHub blob 一致，全部锚点已回读核对。

真机响应体、`string_*.inc` 列表、`executed=true` 的扫描结果见 `EVIDENCE.md`；该文件当前为待填验收模板，本机无 PHP 运行时。

## 定性

该问题属于已公开的旧问题，v5.8.1 包仍在分发。本文不含未公开的 0day。

## 对照结论

- 公开 EXP 入口：`/plus/recommend.php` + `Referer: <?php "system"(whoami);die;/*`
- 本次新增入口：`/plus/flink.php?dopost=save`，验证码失败分支即可触发，无需登录、无需验证码
- 同一 sink 的其他入口：`carbuyaction.php`、`users-reg-new.php`、`users-do.php` 等 58 处
