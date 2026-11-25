# 与公开 EXP 的对比

对照对象：`MzzdToT/Dedecms5.8.1RCE`（120 行 Python，2021-11-22）。

## 逐项

| 维度 | 公开版 | 本仓库 |
| --- | --- | --- |
| 入口数 | 1（`/plus/recommend.php`） | 12 个入口、16 个参数变体 |
| 触发条件 | 空 `aid` | 另有 `flink.php?dopost=save` 验证码失败分支，免验证码 |
| payload | `<?php "system"(whoami);die;/*` | `<?php $m='xxxx'.'yyyy';echo $m;?>`（运行期拼接验证） |
| PHP 8 | `whoami` 裸常量触发 Error，命令不执行 | 函数名变量调用 + base64 参数，7/8 通用 |
| 检测判据 | `status==200 and "location=" in text` | `location=` 判落盘，运行期标记判执行，两档分开 |
| 误报控制 | 无 | 反射内容不含完整标记，反射不会被判成执行 |
| 反应堆 | `findall(r"location='(.*)")[0]` 非 DOTALL，多行会断 | 标记定位，不依赖响应排版 |
| 交互 shell | `die` 截断响应，`findall` 取空后抛 IndexError，实际一直报 timeout | `--cmd` 用随机包裹符取命令输出 |
| 批量 | `import threadpool` 未使用，串行 `for` | `ThreadPoolExecutor`，默认 10 并发 |
| 输入 | `sys.argv[1]` 写在 argparse 之前，无参崩 | argparse 完整校验 |
| 结果 | 仅终端打印 | CSV + JSONL |
| 网络 | 无代理、无重试、无 TLS 开关 | `--proxy` / `--timeout` / `--insecure` |
| 洞见 | 只有入口 | 40+ sink 清单、过滤器 `$token[0]='306'` 赋值错误、后台 10 处写文件、4 条假阳性排除 |

## 公开脚本的四处硬伤（行号对应 120 行原文件）

1. `:13` `filename = sys.argv[1]` 在 argparse 前执行，空参启动即 IndexError。
2. `:38` / `:64` `"system"(whoami)` 的 `whoami` 未加引号，PHP 8 下未定义常量直接 fatal。
3. `:64` 的 `die;` 截断响应，`:71` 的正则取不到 `location=`，异常被吞成 `is timeout`。
4. `:6` 导入 `threadpool` 未使用，`:114` 批量纯串行。

## 评分（五分制）

| 项 | 公开版 | 本仓库 |
| --- | --- | --- |
| 入口覆盖 | 1 | 5 |
| 利用可靠性 | 2 | 4 |
| 工程化 | 2 | 4 |
| 根因深度 | 1 | 5 |
| 开箱即战 | 4 | 4 |
| 综合 | 2.0 | 4.4 |

## 定位差异

公开版是一次性武器：单入口、单发、PHP 7 环境。

本仓库是审计件加工具：能解释同源入口、能区分落盘与执行、能并发跑清单、能输出可归档的结果。
