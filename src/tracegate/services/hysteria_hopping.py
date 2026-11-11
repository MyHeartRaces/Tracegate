"""Hysteria2 UDP port hopping ranges.

Port hopping is rendered by Tracegate as an nftables redirect on the Endpoint;
the Hysteria container gets no extra privileges and never touches the
firewall itself. A range is expressed as ``"LO-HI"`` and redirects to exactly
one obfs listener port.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

HYSTERIA_HOP_PORT_MIN = 1024
HYSTERIA_HOP_PORT_MAX = 65535
HYSTERIA_HOP_RANGE_MAX_SIZE = 30000
HYSTERIA_HOP_MIN_INTERVAL_FLOOR_S = 5

_RANGE_RE = re.compile(r"^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$")


class HysteriaHopRangeError(ValueError):
    pass


def parse_hop_range(value: object, *, label: str = "hop range") -> tuple[int, int] | None:
    """Parse ``"LO-HI"``; an empty value disables hopping."""

    raw = str(value or "").strip()
    if not raw:
        return None
    match = _RANGE_RE.fullmatch(raw)
    if match is None:
        raise HysteriaHopRangeError(f"{label} must use the LO-HI format")
    lower, upper = int(match.group(1)), int(match.group(2))
    if lower >= upper:
        raise HysteriaHopRangeError(f"{label} must satisfy LO < HI")
    if lower < HYSTERIA_HOP_PORT_MIN or upper > HYSTERIA_HOP_PORT_MAX:
        raise HysteriaHopRangeError(
            f"{label} must stay within {HYSTERIA_HOP_PORT_MIN}-{HYSTERIA_HOP_PORT_MAX}"
        )
    if upper - lower + 1 > HYSTERIA_HOP_RANGE_MAX_SIZE:
        raise HysteriaHopRangeError(f"{label} must not exceed {HYSTERIA_HOP_RANGE_MAX_SIZE} ports")
    return lower, upper


def format_hop_range(value: tuple[int, int]) -> str:
    return f"{int(value[0])}-{int(value[1])}"


def validate_hop_ranges(
    ranges: Mapping[str, object],
    *,
    reserved_udp_ports: Iterable[int],
) -> dict[str, tuple[int, int] | None]:
    """Parse every named range and reject overlaps.

    Ranges must not overlap each other nor any reserved public/interconnect
    UDP port (listener ports, the interconnect port and the forbidden port).
    """

    parsed: dict[str, tuple[int, int] | None] = {
        label: parse_hop_range(raw, label=label) for label, raw in ranges.items()
    }
    reserved = sorted({int(port) for port in reserved_udp_ports if int(port or 0) > 0})
    active = [(label, value) for label, value in parsed.items() if value is not None]
    for label, (lower, upper) in active:
        for port in reserved:
            if lower <= port <= upper:
                raise HysteriaHopRangeError(f"{label} overlaps reserved UDP port {port}")
    for index, (label, (lower, upper)) in enumerate(active):
        for other_label, (other_lower, other_upper) in active[index + 1 :]:
            if lower <= other_upper and other_lower <= upper:
                raise HysteriaHopRangeError(f"{label} overlaps {other_label}")
    return parsed


def validate_hop_intervals(min_interval_s: object, max_interval_s: object) -> tuple[int, int]:
    try:
        minimum = int(min_interval_s)
        maximum = int(max_interval_s)
    except (TypeError, ValueError) as exc:
        raise HysteriaHopRangeError("hop intervals must be integers") from exc
    if minimum < HYSTERIA_HOP_MIN_INTERVAL_FLOOR_S:
        raise HysteriaHopRangeError(
            f"minimum hop interval must be at least {HYSTERIA_HOP_MIN_INTERVAL_FLOOR_S}s"
        )
    if maximum <= minimum:
        raise HysteriaHopRangeError("maximum hop interval must be greater than the minimum")
    return minimum, maximum
