#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


API_LINE_RE = re.compile(
    r'^(?P<indent>\s*)"api"\s*:\s*\{\s*"tag"\s*:\s*"api"\s*,\s*"listen"\s*:\s*"127\.0\.0\.1:8080"\s*,\s*"services"\s*:\s*\[\s*"HandlerService"\s*,\s*"StatsService"\s*\]\s*\}\s*,\s*$'
)


def _replace_api_listen_line(text: str) -> tuple[str, int]:
    out: list[str] = []
    changed = 0
    for line in text.splitlines(keepends=True):
        m = API_LINE_RE.match(line.rstrip("\n"))
        if not m:
            out.append(line)
            continue
        indent = m.group("indent")
        out.append(
            "".join(
                [
                    f'{indent}"api": {{\n',
                    f'{indent}  "tag": "api",\n',
                    f'{indent}  "services": [\n',
                    f'{indent}    "HandlerService",\n',
                    f'{indent}    "StatsService"\n',
                    f"{indent}  ]\n",
                    f"{indent}}},\n",
                ]
            )
        )
        changed += 1
    return "".join(out), changed


def _insert_first_array_elem(text: str, *, key: str, elem_text: str, expected: int) -> tuple[str, int]:
    """
    Insert elem_text after the first `"<key>": [` line occurrences.
    Uses a best-effort string patching approach (values file contains Helm templates, not JSON).
    """

    # Example match: <indent>"inbounds": [
    r = re.compile(rf'^(?P<indent>\s*)"{re.escape(key)}"\s*:\s*\[\s*$', re.MULTILINE)

    def repl(m: re.Match) -> str:
        indent = m.group("indent")
        body_indent = indent + "  "
        return m.group(0) + "\n" + "\n".join(body_indent + ln if ln else ln for ln in elem_text.splitlines())

    return r.subn(repl, text, count=expected)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="/root/tracegate-values.yaml", help="Helm values file to patch in-place")
    args = ap.parse_args()

    path = Path(args.path)
    raw = path.read_text(encoding="utf-8")

    patched, replaced = _replace_api_listen_line(raw)
    if replaced != 2:
        raise SystemExit(f"expected to replace 2 api.listen lines, replaced={replaced}")

    # Insert classic Xray API inbound/outbound/routing rule into both gateway xray configs.
    api_inbound = """{
  "tag": "api",
  "listen": "127.0.0.1",
  "port": 8080,
  "protocol": "dokodemo-door",
  "settings": {"address": "127.0.0.1"}
},"""
    patched, inbounds = _insert_first_array_elem(patched, key="inbounds", elem_text=api_inbound, expected=2)
    if inbounds != 2:
        raise SystemExit(f"expected to insert 2 api inbounds, inserted={inbounds}")

    api_outbound = """{
  "protocol": "freedom",
  "tag": "api"
},"""
    patched, outbounds = _insert_first_array_elem(patched, key="outbounds", elem_text=api_outbound, expected=2)
    if outbounds != 2:
        raise SystemExit(f"expected to insert 2 api outbounds, inserted={outbounds}")

    api_rule = """{
  "type": "field",
  "inboundTag": ["api"],
  "outboundTag": "api"
},"""
    patched, rules = _insert_first_array_elem(patched, key="rules", elem_text=api_rule, expected=2)
    if rules != 2:
        raise SystemExit(f"expected to insert 2 api routing rules, inserted={rules}")

    if patched == raw:
        print("no changes")
        return 0

    backup = path.with_suffix(path.suffix + ".bak")
    backup.write_text(raw, encoding="utf-8")
    path.write_text(patched, encoding="utf-8")
    print(f"patched {path} (backup: {backup})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
