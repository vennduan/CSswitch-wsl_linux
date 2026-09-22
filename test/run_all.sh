#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "== python unittest =="
# Windows 下 python3 常是 WindowsApps 商店 stub（命令存在但报错退出），选一个能真跑的
PY=python3
if ! python3 --version >/dev/null 2>&1; then PY=python; fi
"$PY" -m unittest discover -s test -p 'test_*.py' -v
echo "== node --test =="
node --test test/test_make_virtual_oauth.mjs
node --test test/test_desktop_ui_contract.mjs
echo "== bash scripts =="
bash test/test_scripts.sh
echo "== bash ops scripts (doctor/verify-proxy/self-test) =="
bash test/test_ops_scripts.sh
echo "ALL GREEN"
