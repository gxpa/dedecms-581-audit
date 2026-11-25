#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cms_sink_scan.py - 快速白盒 sink 清点器

用法:
    python tools/cms_sink_scan.py <源码根目录> [--out scan.json]

做的事:
  1. 按扩展名识别语言
  2. 用正则抓危险 sink 与输入源
  3. 输出 file:line:kind:text 的 JSON，方便后续手工回溯污点

只做定位，不替代手工污点追踪。
"""
import argparse
import json
import os
import re
import sys

RULES = {
    ".php": {
        "sink_exec": r"\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|eval|assert|create_function)\s*\(",
        "sink_include": r"\b(include|include_once|require|require_once)\s*\(?\s*\$",
        "sink_file": r"\b(file_put_contents|fwrite|fopen|unlink|copy|rename|move_uploaded_file|mkdir)\s*\(",
        "sink_sql": r"(->query\s*\(|->exec\s*\(|mysqli_query\s*\(|mysql_query\s*\(|SetQuery\s*\(|GetOne\s*\(|ExecuteNoneQuery\s*\()",
        "sink_deser": r"\b(unserialize|igbinary_unserialize|yaml_parse)\s*\(",
        "sink_ssrf": r"\b(curl_exec|file_get_contents|fsockopen|stream_socket_client)\s*\(",
        "sink_upload": r"\bmove_uploaded_file\s*\(",
        "source": r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[",
    },
    ".java": {
        "sink_exec": r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|ScriptEngine|SpelExpression|OGNL|XMLDecoder)",
        "sink_sql": r"(createStatement\(|createNativeQuery\(|executeQuery\(|executeUpdate\()",
        "sink_deser": r"(ObjectInputStream|readObject\(|XStream|yaml\.load)",
        "sink_ssrf": r"(new URL\(|HttpClient|OkHttpClient|RestTemplate)",
        "sink_upload": r"(transferTo\(|MultipartFile)",
        "source": r"(getParameter\(|getHeader\(|getCookies\(|@RequestParam|@PathVariable|@RequestBody)",
    },
    ".py": {
        "sink_exec": r"\b(os\.system|os\.popen|subprocess\.(run|Popen|call|check_output)|eval|exec|pickle\.loads|marshal\.loads)\s*\(",
        "sink_sql": r"(\.execute\s*\(|\.executemany\s*\(|RawSQL|\.extra\s*\()",
        "sink_include": r"\b(import_module|__import__)\s*\(",
        "sink_ssrf": r"\b(requests\.(get|post|put)|urllib\.request\.urlopen|httpx\.(get|post))\s*\(",
        "sink_deser": r"\b(yaml\.load|pickle\.load|joblib\.load)\s*\(",
        "source": r"(request\.(args|form|values|json|files|headers|get_json)|self\.get_argument)",
    },
    ".js": {
        "sink_exec": r"\b(child_process\.(exec|execSync|spawn)|eval|new Function|vm\.runIn\w*)\s*\(",
        "sink_sql": r"(\.query\s*\(|\.raw\s*\(|knex\.raw)",
        "sink_ssrf": r"\b(fetch|axios\.(get|post)|http\.request)\s*\(",
        "sink_xss": r"(innerHTML\s*=|dangerouslySetInnerHTML|document\.write)",
        "sink_upload": r"(multer|busboy|formidable)",
        "source": r"(req\.(query|body|params|headers|cookies)|ctx\.request)",
    },
}

EXTS = {".php", ".java", ".py", ".js", ".ts"}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__"}


def lang_of(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".ts":
        ext = ".js"
    return ext if ext in RULES else None


def scan(root):
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            lang = lang_of(path)
            if not lang:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            rules = RULES[lang]
            compiled = {k: re.compile(v) for k, v in rules.items()}
            for lineno, line in enumerate(lines, 1):
                for kind, rx in compiled.items():
                    if rx.search(line):
                        hits.append({
                            "file": os.path.relpath(path, root).replace("\\", "/"),
                            "line": lineno,
                            "kind": kind,
                            "code": line.strip()[:300],
                        })
    return hits


def summarize(hits):
    out = {}
    for h in hits:
        key = h["kind"]
        out.setdefault(key, {"count": 0, "files": set()})
        out[key]["count"] += 1
        out[key]["files"].add(h["file"])
    return {k: {"count": v["count"], "files": len(v["files"])} for k, v in sorted(out.items())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    if not os.path.isdir(args.root):
        print("not a directory: %s" % args.root, file=sys.stderr)
        return 2
    hits = scan(args.root)
    summary = summarize(hits)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"root": os.path.abspath(args.root), "summary": summary, "hits": hits},
                      fh, ensure_ascii=False, indent=2)
        print("written: %s (%d hits)" % (args.out, len(hits)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
