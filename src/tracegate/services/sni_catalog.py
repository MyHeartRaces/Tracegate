from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

import yaml

# Operators supply the real camouflage SNI catalog out-of-band. The catalog
# committed to this public repository is a documentation-reserved placeholder so
# that working camouflage fronts are not published. Point this environment
# variable at a readable YAML file (e.g. a mounted private Secret/ConfigMap) to
# override the bundled placeholder catalog at runtime.
SNI_CATALOG_FILE_ENV = "TRACEGATE_SNI_CATALOG_FILE"
BLOCKED_SNI_ROOTS = frozenset({"max.ru"})


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


def sni_root_domain(fqdn: str) -> str:
    """Return the operational root used to prevent sibling-subdomain reuse.

    Production camouflage domains currently use ordinary two-label ``.ru`` or
    ``.net`` roots. Keeping this deliberately strict avoids silently treating
    multiple subdomains of the same provider as independent SNI diversity.
    """

    labels = [label for label in str(fqdn or "").strip().lower().rstrip(".").split(".") if label]
    if len(labels) < 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def is_blocked_sni(fqdn: str) -> bool:
    return sni_root_domain(fqdn) in BLOCKED_SNI_ROOTS


def _catalog_yaml_text() -> str:
    # A private override (mounted file) takes precedence so production runs on the
    # real catalog while the public image ships only the placeholder.
    override = os.environ.get(SNI_CATALOG_FILE_ENV, "").strip()
    if override:
        candidate = Path(override)
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    # Package data is included into the wheel/container image (placeholder catalog).
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
