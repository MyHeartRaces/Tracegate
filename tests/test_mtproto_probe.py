from __future__ import annotations

from argparse import Namespace
import asyncio
import json

import pytest

from scripts import probe_mtproto


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("00112233445566778899AABBCCDDEEFF\n", "00112233445566778899aabbccddeeff"),
        ("dd00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeff"),
    ],
)
def test_normalize_random_padding_secret(raw: str, expected: str) -> None:
    assert probe_mtproto._normalize_random_padding_secret(raw) == expected


@pytest.mark.parametrize("raw", ["", "0011", "ee00112233445566778899aabbccddeeff2e7275"])
def test_normalize_random_padding_secret_rejects_invalid_values(raw: str) -> None:
    with pytest.raises(ValueError):
        probe_mtproto._normalize_random_padding_secret(raw)


def test_probe_summary_does_not_include_secret(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    async def fake_probe(_args: Namespace, _secret: str) -> dict[str, object]:
        return {"ok": True, "auth_key_bytes": 256, "duration_seconds": 0.1}

    monkeypatch.setattr(probe_mtproto, "_probe_once", fake_probe)
    args = Namespace(attempts=2, delay=0.0)

    assert asyncio.run(probe_mtproto._run(args, "00112233445566778899aabbccddeeff")) == 0
    output = capsys.readouterr().out
    rows = [json.loads(line) for line in output.splitlines()]
    assert rows[-1] == {"attempts": 2, "failed": 0, "successful": 2, "summary": True}
    assert "00112233445566778899aabbccddeeff" not in output
