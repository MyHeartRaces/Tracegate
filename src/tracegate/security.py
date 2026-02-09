from fastapi import Header, HTTPException, status

from tracegate.settings import get_settings


async def require_internal_api_token(x_api_token: str | None = Header(default=None)) -> None:
    expected = get_settings().api_internal_token
    if not expected:
        return
    if x_api_token != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API token")


async def require_agent_token(x_agent_token: str | None = Header(default=None)) -> None:
    expected = get_settings().agent_auth_token
    if not expected:
        return
    if x_agent_token != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")
