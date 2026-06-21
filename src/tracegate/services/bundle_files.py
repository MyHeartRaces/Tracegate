from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

BundleFilePayload = str | dict[str, str]


def decode_bundle_file_content(content: Any) -> bytes:
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    if not isinstance(content, dict):
        raise ValueError(f"unsupported bundle file payload type: {type(content).__name__}")

    encoding = str(content.get("encoding") or "").strip().lower()
    raw_content = content.get("content")
    if not isinstance(raw_content, str):
        raise ValueError("structured bundle file payload must include string content")

    if encoding in {"text", "utf-8", "utf8"}:
        return raw_content.encode("utf-8")
    if encoding in {"base64", "b64"}:
        try:
            return base64.b64decode(raw_content, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("invalid base64 bundle file payload") from exc

    raise ValueError(f"unsupported bundle file encoding: {encoding or 'missing'}")


def encode_bundle_file_content(content: bytes) -> BundleFilePayload:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "encoding": "base64",
            "content": base64.b64encode(content).decode("ascii"),
        }


def load_bundle_file(path: Path) -> BundleFilePayload:
    return encode_bundle_file_content(path.read_bytes())
