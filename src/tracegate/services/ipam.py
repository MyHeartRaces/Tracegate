from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.enums import IpamLeaseStatus, OwnerType
from tracegate.models import IpamLease, IpamPool


class IpamError(RuntimeError):
    pass


async def ensure_pool_exists(
    session: AsyncSession,
    cidr: str = "10.70.0.0/24",
    gateway: str = "10.70.0.1",
    quarantine_seconds: int = 1800,
) -> IpamPool:
    pool = await session.scalar(select(IpamPool).where(IpamPool.cidr == cidr))
    if pool:
        return pool

    pool = IpamPool(cidr=cidr, gateway=gateway, quarantine_seconds=quarantine_seconds)
    session.add(pool)
    await session.flush()
    return pool


def iter_candidate_ips(pool: IpamPool) -> list[str]:
    network = ipaddress.ip_network(pool.cidr)
    gateway = ipaddress.ip_address(pool.gateway)
    ips: list[str] = []
    for host in network.hosts():
        if host == gateway:
            continue
        ips.append(str(host))
    return ips


async def allocate_lease(
    session: AsyncSession,
    pool: IpamPool,
    owner_type: OwnerType,
    owner_id: uuid.UUID,
) -> IpamLease:
    now = datetime.now(timezone.utc)

    existing = await session.scalar(
        select(IpamLease).where(
            IpamLease.pool_id == pool.id,
            IpamLease.owner_type == owner_type,
            IpamLease.owner_id == owner_id,
            IpamLease.status == IpamLeaseStatus.ACTIVE,
        )
    )
    if existing:
        return existing

    candidates = iter_candidate_ips(pool)
    busy = {
        ip
        for ip, status, until in (
            await session.execute(
                select(IpamLease.ip, IpamLease.status, IpamLease.quarantined_until).where(IpamLease.pool_id == pool.id)
            )
        ).all()
        if status == IpamLeaseStatus.ACTIVE or (status == IpamLeaseStatus.QUARANTINED and until and until > now)
    }

    for ip in candidates:
        if ip in busy:
            continue
        lease = IpamLease(pool_id=pool.id, ip=ip, owner_type=owner_type, owner_id=owner_id, status=IpamLeaseStatus.ACTIVE)
        session.add(lease)
        await session.flush()
        return lease

    raise IpamError("IPAM pool exhausted")


async def release_lease(session: AsyncSession, lease: IpamLease, quarantine_seconds: int | None = None) -> IpamLease:
    if quarantine_seconds is None:
        pool: IpamPool | None = await session.scalar(select(IpamPool).where(IpamPool.id == lease.pool_id))
        quarantine_seconds = pool.quarantine_seconds if pool else 1800

    lease.status = IpamLeaseStatus.QUARANTINED
    lease.quarantined_until = datetime.now(timezone.utc) + timedelta(seconds=quarantine_seconds)
    await session.flush()
    return lease


async def reap_quarantine(session: AsyncSession) -> int:
    now = datetime.now(timezone.utc)
    stmt: Select[tuple[IpamLease]] = select(IpamLease).where(
        IpamLease.status == IpamLeaseStatus.QUARANTINED,
        IpamLease.quarantined_until.is_not(None),
        IpamLease.quarantined_until <= now,
    )
    rows = (await session.execute(stmt)).scalars().all()
    for row in rows:
        row.status = IpamLeaseStatus.RELEASED
    await session.flush()
    return len(rows)
