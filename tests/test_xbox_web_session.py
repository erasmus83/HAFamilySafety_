"""Xbox features keep the Family web session warm and noticed (#52).

Since #64 the schedules use the mobile API, so the Xbox calls are the only
Family web requests left. These checks cover what that changed:

- the coordinator bootstraps the Family context itself when Xbox is on;
- an isolated 401 or login redirect drops the context (403/404 still only
  means "no Xbox"), and an isolated 2xx proves the session;
- the reauth prompt is kept while Xbox features are on;
- the +8 h / +16 h silent renewals do not prompt, the +24 h expiry does;
- an "allowUntil" Xbox override reads as not blocked.

The real modules are loaded without Home Assistant (the HA imports are
stubbed), so this needs only:

    pip install aiohttp yarl httpx python-dateutil pyfamilysafety==1.1.2

Run with ``pytest tests/`` or ``python tests/test_xbox_web_session.py``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import importlib
import json
from pathlib import Path
import sys
import time
import types

COMPONENT = Path(__file__).resolve().parents[1] / "custom_components" / "microsoft_family_safety"


# --- Home Assistant stubs ----------------------------------------------------
def _module(name: str, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


class _Any:
    def __init__(self, *args, **kwargs):
        pass

    def __class_getitem__(cls, item):
        return cls


class _HAError(Exception):
    pass


class _UpdateFailed(Exception):
    pass


_module("homeassistant")
_module("homeassistant.helpers")
_module("homeassistant.util")
_module("homeassistant.core", HomeAssistant=_Any, callback=lambda func: func)
_module("homeassistant.config_entries", ConfigEntry=_Any)
_module("homeassistant.exceptions", ConfigEntryAuthFailed=_HAError, HomeAssistantError=_HAError)
_module("homeassistant.helpers.storage", Store=_Any)
_module(
    "homeassistant.helpers.update_coordinator",
    DataUpdateCoordinator=_Any,
    UpdateFailed=_UpdateFailed,
)
dt_util = _module(
    "homeassistant.util.dt",
    now=lambda: datetime.now(timezone.utc),
    utcnow=lambda: datetime.now(timezone.utc),
)
sys.modules["homeassistant.util"].dt = dt_util
_module("homeassistant.helpers.aiohttp_client", async_get_clientsession=lambda hass: None)
_module("cryptography")
_module("cryptography.fernet", Fernet=_Any)

# Load the component's modules without running its __init__ (which needs HA).
_module("mfs").__path__ = [str(COMPONENT)]
_module("mfs.auth").__path__ = [str(COMPONENT / "auth")]
api_client = importlib.import_module("mfs.api_client")
coordinator = importlib.import_module("mfs.coordinator")
WebAPI = api_client.FamilySafetyWebAPI
Coordinator = coordinator.FamilySafetyDataUpdateCoordinator

XBOX_URL = "https://account.microsoft.com/family/api/xbox/screen-time-xbox"


# --- fake Family web session -------------------------------------------------
class _Response:
    def __init__(self, status: int, location: str | None = None, body: str = "{}"):
        self.status = status
        self.headers = {"Location": location} if location else {}
        self.url = XBOX_URL
        self._body = body

    async def text(self):
        return self._body

    async def json(self, content_type=None):
        return json.loads(self._body)


class _Context:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *exc):
        return False


class _Jar(list):
    def filter_cookies(self, url):
        return {}


class _Session:
    def __init__(self, response):
        self._response = response
        self.cookie_jar = _Jar()

    def request(self, *args, **kwargs):
        return _Context(self._response)


def _web_api(response: _Response):
    api = WebAPI(authenticator=object())
    api._web_cookies = [{"name": "MSPAuth", "value": "x", "domain": ".live.com", "path": "/"}]
    api._web_csrf = "token"
    api.family_context_state = "ready"
    api.family_token_source = "auth_proxy"
    api._family_referer = "https://account.microsoft.com/family/home"
    session = _Session(response)
    api._get_web_session = lambda: session
    api.sync_web_cookies_from_session = lambda: False
    return api


def _request(api):
    return asyncio.run(api._web_request("GET", XBOX_URL, isolated=True))


# --- isolated Xbox requests --------------------------------------------------
def test_isolated_401_drops_the_family_context():
    api = _web_api(_Response(401, body='{"statusCode":401}'))
    assert _request(api) is None
    assert api.family_context_state == "auth_required"
    assert api._web_csrf is None
    assert api.family_context_dropped is True
    assert api.last_isolated_error_code == "HTTP_401"
    assert api.web_session_state != "expired"


def test_isolated_403_keeps_the_context():
    # A child without an Xbox answers 403; that says nothing about the session.
    api = _web_api(_Response(403, body='{"statusCode":403}'))
    api.web_session_state = "unknown"
    _request(api)
    assert api.family_context_state == "ready"
    assert api._web_csrf == "token"
    assert api.web_session_state == "unknown"


def test_isolated_login_redirect_drops_the_context():
    login = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=login"
    api = _web_api(_Response(302, location=login))
    _request(api)
    assert api.family_context_state == "auth_required"
    assert api._web_csrf is None


def test_isolated_other_redirect_keeps_the_context():
    api = _web_api(_Response(302, location="https://account.microsoft.com/family/home"))
    _request(api)
    assert api.family_context_state == "ready"


def test_isolated_success_proves_the_session():
    api = _web_api(_Response(200, body='{"ok": true}'))
    api.web_session_state = "unknown"
    _request(api)
    assert api.web_session_state == "authenticated"


# --- reauth escalation -------------------------------------------------------
def _tracking_coordinator(*, mobile_only: bool = False):
    coord = object.__new__(Coordinator)
    coord._mobile_only = mobile_only
    coord._has_web_credentials = True
    coord._family_auth_required_polls = 0
    coord._reauth_requested = False
    coord._reauth_reason = None
    coord.web_api = types.SimpleNamespace(
        family_context_state="auth_required", mobile_schedule_ok=True
    )
    coord.calls = []

    async def notify():
        coord.calls.append("notify")

    coord._create_auth_notification = notify
    coord._request_reauth = lambda reason: coord.calls.append(reason)
    return coord


def test_xbox_on_keeps_the_reauth_prompt():
    coord = _tracking_coordinator()
    asyncio.run(coord._async_track_family_context())
    assert coord.calls == []
    asyncio.run(coord._async_track_family_context())
    assert "family_context_auth_required" in coord.calls


def test_mobile_only_never_prompts():
    coord = _tracking_coordinator(mobile_only=True)
    asyncio.run(coord._async_track_family_context())
    asyncio.run(coord._async_track_family_context())
    assert coord.calls == []


# --- bootstrap at the start of a poll ----------------------------------------
class _StopPoll(Exception):
    pass


def _poll_warms(state: str, *, mobile_only=False, backoff=0.0, cookies=True) -> bool:
    coord = object.__new__(Coordinator)
    coord._mobile_only = mobile_only
    coord._has_web_credentials = True
    coord._family_auth_required_polls = 0
    coord._reauth_requested = False
    coord._reauth_reason = None
    warmed = []

    async def warm():
        warmed.append(True)

    async def probe():
        return True

    async def noop(*args, **kwargs):
        return None

    async def stop():
        raise _StopPoll

    coord.web_api = types.SimpleNamespace(
        family_context_state=state,
        has_web_cookies=cookies,
        _family_web_backoff_until=backoff,
        _warm_family_context=warm,
        async_check_web_session=probe,
        web_session_state="authenticated",
    )
    coord._async_load_web_cookies = noop
    coord._dismiss_auth_notification = noop
    coord._async_persist_current_auth = noop
    coord.api = types.SimpleNamespace(update=stop)  # stop right after the warm-up
    try:
        asyncio.run(coord._async_update_data())
    except BaseException:  # noqa: BLE001 - the poll is cut short on purpose
        pass
    return bool(warmed)


def test_poll_bootstraps_when_xbox_needs_the_context():
    assert _poll_warms("unknown")  # after a restart without a stored token
    assert _poll_warms("auth_required")


def test_poll_leaves_a_ready_or_unneeded_context_alone():
    assert not _poll_warms("ready")
    assert not _poll_warms("unknown", mobile_only=True)
    assert not _poll_warms("unknown", backoff=time.monotonic() + 600)
    assert not _poll_warms("unknown", cookies=False)


# --- poll sequences ----------------------------------------------------------
def _reauth_polls(polls) -> list[int]:
    """Replay polls of (xbox_401, [bootstrap outcomes]); return the polls that prompted."""
    api = _web_api(_Response(200))
    outcomes: list[str] = []

    async def warm():
        api.family_context_state = outcomes.pop(0)
        if api.family_context_state == "ready":
            api._web_csrf = "token"
        return api._web_csrf

    api._warm_family_context = warm
    coord = object.__new__(Coordinator)
    coord._mobile_only = False
    coord._has_web_credentials = True
    coord.web_api = api
    coord._family_auth_required_polls = 0
    coord._reauth_requested = False
    coord._reauth_reason = None

    async def notify():
        return None

    coord._create_auth_notification = notify
    prompted: list[int] = []

    async def run():
        for number, (xbox_401, results) in enumerate(polls, 1):
            outcomes[:] = list(results)
            coord._request_reauth = lambda reason, n=number: prompted.append(n)
            if api.family_context_state != "ready":
                await api._warm_family_context()
            if xbox_401 and api.family_context_state == "ready":
                api._drop_family_context()
            await coord._async_rewarm_dropped_family_context()
            await coord._async_track_family_context()

    asyncio.run(run())
    return prompted


def test_silent_renewal_dips_do_not_prompt():
    # +8 h / +16 h: the bootstrap ends on the silent sign-in page once, then recovers.
    assert _reauth_polls([(True, ["auth_required"]), (False, ["ready"]), (False, [])]) == []


def test_24h_expiry_prompts_on_the_second_failed_poll():
    polls = [(True, ["auth_required"]), (False, ["auth_required"]), (False, ["auth_required"])]
    assert _reauth_polls(polls)[:1] == [2]


def test_healthy_session_never_prompts():
    assert _reauth_polls([(False, []), (False, []), (False, [])]) == []


# --- Xbox lock state ---------------------------------------------------------
def _lock_state(override, *, known_block=False):
    coord = object.__new__(Coordinator)
    coord._platform_override_until = {}
    coord._xbox_lock_known = set()
    if known_block:
        coord._platform_override_until[("42", "xbox")] = dt_util.utcnow() + timedelta(hours=5)
        coord._xbox_lock_known.add("42")
    data = {"dailyRestrictions": {}}
    if override is not None:
        data["screenTimeOverride"] = override
    account = {"blocked_platforms": []}
    coord._apply_xbox_lock_state("42", account, {"data": data})
    return "42" in coord._xbox_lock_known, "Xbox" in account["blocked_platforms"]


def test_allow_until_reads_as_not_blocked():
    allow = {"screenTimeOverrideType": "AllowUntil", "validUntil": "2026-10-28T20:00:00Z"}
    assert _lock_state(allow) == (True, False)
    assert _lock_state(allow, known_block=True) == (True, False)


def test_block_until_and_unknown_types_unchanged():
    until = (dt_util.utcnow() + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert _lock_state({"screenTimeOverrideType": "BlockUntil", "validUntil": until}) == (True, True)
    assert _lock_state({"screenTimeOverrideType": "SomethingNew"}) == (False, False)


if __name__ == "__main__":
    import logging

    logging.disable(logging.CRITICAL)
    failures = 0
    for name, func in list(globals().items()):
        if name.startswith("test_") and callable(func):
            try:
                func()
                print(f"PASS {name}")
            except AssertionError as err:
                failures += 1
                print(f"FAIL {name} {err}")
    print("ALL PASSED" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
