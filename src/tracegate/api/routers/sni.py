from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from tracegate.schemas import SniDomainRead
from tracegate.security import require_internal_api_token
from tracegate.services.sni_catalog import load_catalog
from tracegate.settings import get_settings

router = APIRouter(prefix="/sni", tags=["sni"], dependencies=[Depends(require_internal_api_token)])


@router.get("", response_model=list[SniDomainRead])
async def list_sni(
    provider: str | None = Query(default=None),
    enabled_only: bool = Query(default=True),
    purpose: str | None = Query(default=None),
) -> list[SniDomainRead]:
    rows = load_catalog()
    if enabled_only:
        rows = [r for r in rows if r.enabled]

    if provider:
        p = provider.strip().lower()
        if p in {"other", "unknown", "none"}:
            rows = [r for r in rows if not (r.providers or [])]
        else:
            rows = [r for r in rows if p in (r.providers or [])]

    if purpose:
        # REALITY uses a single `dest`, so we must only show compatible SNIs (optional policy).
        if purpose.strip().lower() in {"vless", "vless_reality", "reality"}:
            settings = get_settings()
            suffixes = [s.lower().strip() for s in settings.reality_sni_allow_suffixes if s.strip()]

            def allowed(fqdn: str) -> bool:
                name = fqdn.lower().strip()
                for suf in suffixes:
                    if suf.startswith("."):
                        if name.endswith(suf):
                            return True
                    else:
                        if name == suf or name.endswith("." + suf):
                            return True
                return False

            if suffixes:
                rows = [r for r in rows if allowed(r.fqdn)]

    rows.sort(key=lambda r: r.fqdn.lower())
    return [
        SniDomainRead(
            id=r.id,
            fqdn=r.fqdn,
            enabled=r.enabled,
            is_test=r.is_test,
            note=r.note,
            providers=r.providers or [],
        )
        for r in rows
    ]

