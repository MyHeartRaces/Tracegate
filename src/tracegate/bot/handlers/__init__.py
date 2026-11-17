"""Bot routers, one per area.

Order matters for messages: routers with command handlers (start, guide,
admin's /announce) come before the routers whose FSM text handlers would
otherwise swallow a command typed mid-flow. ``fallback`` must stay last.
"""

from __future__ import annotations

from aiogram import Router


def build_routers() -> list[Router]:
    from tracegate.bot.handlers import admin, connections, devices, fallback, feedback, guide, mtproto, start

    return [
        start.router,
        guide.router,
        admin.router,
        devices.router,
        connections.router,
        mtproto.router,
        feedback.router,
        fallback.router,
    ]
