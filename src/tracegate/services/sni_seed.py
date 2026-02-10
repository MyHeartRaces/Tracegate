from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.models import SniDomain
from tracegate.services.sni_catalog import load_default_catalog
from tracegate.settings import get_settings


async def seed_sni(session: AsyncSession) -> None:
    """
    Seed SNI domains into DB.

    - Loads the built-in catalog (with provider tags + notes)
    - Also seeds any extra domains from settings.sni_seed (strings), without provider tags.
    """

    # Built-in catalog.
    for entry in load_default_catalog():
        existing = await session.scalar(select(SniDomain).where(SniDomain.fqdn == entry.fqdn))
        if existing is None:
            session.add(
                SniDomain(
                    fqdn=entry.fqdn,
                    enabled=True,
                    is_test=False,
                    note=entry.note,
                    providers=entry.providers,
                )
            )
            continue

        # Merge without overwriting manual changes aggressively.
        changed = False
        if entry.note and not existing.note:
            existing.note = entry.note
            changed = True
        merged = sorted(set((existing.providers or [])).union(entry.providers or []))
        if merged != (existing.providers or []):
            existing.providers = merged
            changed = True
        if changed:
            session.add(existing)

    # Extra domains from environment settings (optional).
    settings = get_settings()
    for fqdn in settings.sni_seed:
        existing = await session.scalar(select(SniDomain).where(SniDomain.fqdn == fqdn))
        if existing is None:
            session.add(SniDomain(fqdn=fqdn, enabled=True, is_test=True, note=None, providers=[]))

