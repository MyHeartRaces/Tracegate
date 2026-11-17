from __future__ import annotations

from aiogram.fsm.state import State, StatesGroup


class DeviceFlow(StatesGroup):
    waiting_for_name = State()
    waiting_for_rename = State()


class FeedbackFlow(StatesGroup):
    waiting_for_message = State()


class AdminFlow(StatesGroup):
    waiting_for_grant_id = State()
    waiting_for_revoke_id = State()
    waiting_for_mtproto_revoke_id = State()
    waiting_for_user_access_revoke_id = State()
    waiting_for_user_access_revoke_notify = State()
    waiting_for_user_block = State()
    waiting_for_user_unblock = State()
    waiting_for_announce_text = State()
