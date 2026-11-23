"""The OIDF runner's reading of the suite's module logs (tools/oidf/run.py), on logs as the suite writes them."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("oidf_run", ROOT / "tools" / "oidf" / "run.py")
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
sys.modules["oidf_run"] = run
spec.loader.exec_module(run)

AUTHORIZE = f"{run.ISSUER}/authorize?client_id=https://wallet-solution.test&request_uri=urn:x"
CALLBACK = "https://localhost.emobix.co.uk:8443/test/a/cunho/callback?code=c"
ASK = {"msg": "If the server does not return an error back to the client, It must show an error page", "upload": "p1"}
REQUEST = {"msg": "Scripted browser HTTP request"}
REFUSED = {"msg": "Scripted browser HTTP response", "response_status_code": "400"}
MISMATCH = {"msg": "Skipping optional task due to URL mismatch", "url": AUTHORIZE}
LATE = {"msg": "Completed processing of webpage", "response_status_code": "200", "url": CALLBACK}


def test_a_refusal_logged_right_after_the_request_for_a_screenshot_is_answered() -> None:
    log: list[dict[str, Any]] = [ASK, REQUEST, REFUSED, MISMATCH, LATE]
    assert run.refused_after(log) == ["p1"]


def test_a_late_entry_for_an_earlier_page_between_them_does_not_hide_the_refusal() -> None:
    # As the suite logged it on 23 Nov 2026: the browser's note about the callback page came first.
    log: list[dict[str, Any]] = [ASK, LATE, REQUEST, REFUSED, MISMATCH]
    assert run.refused_after(log) == ["p1"]


def test_no_refusal_or_a_refusal_elsewhere_is_not_answered() -> None:
    assert run.refused_after([ASK, REQUEST, {**REFUSED, "response_status_code": "200"}, MISMATCH]) == []
    elsewhere = {**MISMATCH, "url": CALLBACK}
    assert run.refused_after([ASK, REQUEST, REFUSED, elsewhere]) == []
    assert run.refused_after([REQUEST, REFUSED, MISMATCH]) == []
