from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

import yaml


@dataclass(frozen=True)
class SniCatalogEntry:
    """
    Static SNI "database".

    Source of truth is `tracegate.staticdata/sni_catalog.yaml`, committed to Git.
    The runtime Postgres DB must NOT store/own SNI rows (only dynamic state such as users/devices/connections).
    """

    id: int
    fqdn: str
    enabled: bool
    is_test: bool
    providers: list[str]
    note: str | None


def _catalog_yaml_text() -> str:
    # Package data is included into the wheel/container image.
    path = files("tracegate.staticdata").joinpath("sni_catalog.yaml")
    return path.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def load_catalog() -> list[SniCatalogEntry]:
    raw = yaml.safe_load(_catalog_yaml_text()) or []
    if not isinstance(raw, list):
        raise ValueError("Invalid static SNI catalog format (expected a YAML list)")

    out: list[SniCatalogEntry] = []
    seen: set[int] = set()
    for row in raw:
        if not isinstance(row, dict):
            continue
        sni_id = int(row.get("id"))
        if sni_id in seen:
            raise ValueError(f"Duplicate SNI id in static catalog: {sni_id}")
        seen.add(sni_id)
        out.append(
            SniCatalogEntry(
                id=sni_id,
                fqdn=str(row.get("fqdn") or "").strip(),
                enabled=bool(row.get("enabled", True)),
                is_test=bool(row.get("is_test", False)),
                note=(str(row.get("note")).strip() if row.get("note") is not None else None) or None,
                providers=[str(p).strip().lower() for p in (row.get("providers") or []) if str(p).strip()],
            )
        )

    out.sort(key=lambda e: e.id)
    return out


@lru_cache(maxsize=2048)
def get_by_id(sni_id: int) -> SniCatalogEntry | None:
    for row in load_catalog():
        if row.id == sni_id:
            return row
    return None

