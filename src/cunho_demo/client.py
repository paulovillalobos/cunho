"""The demo's side of cunho's admin API: each call the demo makes, with the operator token, and nothing else."""

from __future__ import annotations

import ssl
from typing import Any
from urllib.parse import quote

import httpx

from cunho_demo.settings import IssuerLink

TIMEOUT = httpx.Timeout(5.0)


class CunhoError(Exception):
    """cunho refused, or could not be reached (status 503 then)."""

    def __init__(self, status: int, error: str, description: str = "") -> None:
        super().__init__(f"{status} {error}: {description}")
        self.status = status
        self.error = error
        self.description = description


class Cunho:
    def __init__(self, link: IssuerLink, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(
            base_url=link.url.rstrip("/"),
            headers={"Authorization": f"Bearer {link.token}"},
            timeout=TIMEOUT,
            transport=transport,
            follow_redirects=False,
            verify=ssl.create_default_context(cafile=str(link.ca_file)) if link.ca_file else True,
        )

    async def _call(self, method: str, path: str, body: Any = None) -> Any:
        try:
            response = await self._client.request(method, path, json=body)
        except httpx.HTTPError as exc:
            raise CunhoError(503, "unavailable", type(exc).__name__) from exc
        if response.status_code >= 400:
            try:
                answer = response.json()
            except ValueError:
                answer = {}
            error = answer.get("error") if isinstance(answer, dict) else None
            description = answer.get("error_description") if isinstance(answer, dict) else None
            raise CunhoError(response.status_code, str(error or "error"), str(description or ""))
        return response.json() if response.content else None

    async def create_offer(self, body: dict[str, Any]) -> dict[str, Any]:
        answer: dict[str, Any] = await self._call("POST", "/admin/offers", body)
        return answer

    async def progress(self, subject_ref: str) -> dict[str, Any]:
        answer: dict[str, Any] = await self._call("GET", f"/admin/offers/{quote(subject_ref, safe='')}")
        return answer

    async def pending_login(self, login_state: str) -> dict[str, Any]:
        answer: dict[str, Any] = await self._call("GET", f"/admin/logins/{quote(login_state, safe='')}")
        return answer

    async def report_login(self, login_state: str, body: dict[str, Any]) -> dict[str, Any]:
        answer: dict[str, Any] = await self._call("POST", f"/admin/logins/{quote(login_state, safe='')}", body)
        return answer

    async def revoke(self, subject_ref: str) -> dict[str, Any]:
        body = {"subject_ref": subject_ref, "reason": "user_request"}
        answer: dict[str, Any] = await self._call("POST", "/admin/revocations", body)
        return answer

    async def deferred(self) -> list[dict[str, Any]]:
        answer = await self._call("GET", "/admin/deferred")
        return list(answer["deferred"])

    async def decide(self, ref: str, decision: str) -> dict[str, Any]:
        answer: dict[str, Any] = await self._call("POST", f"/admin/deferred/{quote(ref, safe='')}/{decision}")
        return answer

    async def audit_verify(self) -> dict[str, Any]:
        answer: dict[str, Any] = await self._call("GET", "/admin/audit/verify")
        return answer

    async def aclose(self) -> None:
        await self._client.aclose()
