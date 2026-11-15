"""Regression tests for the fifth M2 review (cunho-m2-review-5.md): JSON input and boolean settings."""

from __future__ import annotations

import pytest

from cunho.errors import ConfigError
from cunho.jose import JoseError, b64u, parse_jws, strict_json
from cunho.settings import Settings

from .helpers import Pki, settings_kwargs
from .test_review3_fixes import _env

# N5-L11: JSON is UTF-8, and settings say true or false ------------------------------------------------


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-32"])
def test_n5_l11_json_in_another_encoding_is_refused(encoding: str) -> None:
    """t13: `json.loads` detects UTF-16 and UTF-32 in bytes; RFC 8259 §8.1 allows only UTF-8 between systems."""
    with pytest.raises(ValueError):
        strict_json('{"a": 1}'.encode(encoding))
    assert strict_json('{"a": "é"}'.encode()) == {"a": "é"}
    with pytest.raises(JoseError) as caught:
        parse_jws(f"{b64u('{}'.encode(encoding))}.{b64u(b'{}')}.AA")
    assert str(caught.value) == "header or payload is not valid JSON", "no byte of the input is echoed"


def test_n5_l11_boolean_settings(pki: Pki) -> None:
    def production(value: str) -> bool:
        env = {**_env(pki), "CUNHO_DPOP_SERVER_NONCE": value}
        return Settings.from_env(env).dpop_server_nonce

    assert [production(v) for v in ("true", "1", "yes", "ON", "false", "0", "no", "off", "")] == [True] * 4 + [
        False
    ] * 5
    with pytest.raises(ConfigError, match="CUNHO_PRODUCTION must be true or false"):
        Settings.from_env({**_env(pki), "CUNHO_PRODUCTION": "ture"})
    assert Settings.from_env({**_env(pki), "CUNHO_STATUS_PUBLISH_INTERVAL": "30"}).status_publish_interval == 30
    assert Settings.from_env({**_env(pki), "CUNHO_STATUS_RATE_LIMIT_PER_MINUTE": "9"}).status_rate_limit_per_minute == 9
    with pytest.raises(ConfigError, match="status_publish_interval must be at most"):
        Settings(**settings_kwargs(pki, status_publish_interval=3601, status_token_ttl=7200))
    with pytest.raises(ConfigError, match="status_publish_interval must be at most"):
        Settings(**settings_kwargs(pki, status_publish_interval=601, status_token_ttl=600))
    Settings(**settings_kwargs(pki, status_publish_interval=3600, status_token_ttl=7200))
    Settings(**settings_kwargs(pki, status_publish_interval=600, status_token_ttl=600))
