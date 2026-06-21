import pytest
from fastapi import HTTPException

from tracegate.enums import ApiScope
from tracegate.security import ApiPrincipal, _has_scope, _normalize_scopes, require_api_scope


def _principal(scopes: set[str]) -> ApiPrincipal:
    return ApiPrincipal(token_id="tok", token_name="test", scopes=frozenset(scopes), is_bootstrap=False)


def test_normalize_scopes_defaults_to_all() -> None:
    assert _normalize_scopes(None) == frozenset({ApiScope.ALL.value})
    assert _normalize_scopes([]) == frozenset({ApiScope.ALL.value})


def test_scope_matching_rw_covers_read_write() -> None:
    scopes = frozenset({ApiScope.USERS_RW.value})
    assert _has_scope(scopes, "users:read")
    assert _has_scope(scopes, "users:write")
    assert not _has_scope(scopes, "nodes:rw")


@pytest.mark.asyncio
async def test_require_api_scope_allows_matching_principal() -> None:
    dependency = require_api_scope(ApiScope.USERS_ROLE)
    principal = _principal({ApiScope.USERS_ROLE.value})

    resolved = await dependency(principal=principal)

    assert resolved is principal


@pytest.mark.asyncio
async def test_require_api_scope_rejects_missing_scope() -> None:
    dependency = require_api_scope(ApiScope.USERS_ROLE)
    principal = _principal({ApiScope.USERS_RW.value})

    with pytest.raises(HTTPException) as exc:
        await dependency(principal=principal)

    assert exc.value.status_code == 403
