"""What the demo offers: the credentials, the fictional people they are about, and how cunho's progress of an offer
reads as the steps the page shows."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cunho_demo.texts import shown

PID_SD_JWT = "eu.europa.ec.eudi.pid_vc_sd_jwt"
PID_MDOC = "eu.europa.ec.eudi.pid_mdoc"
COURSE_SD_JWT = "app.foaap.course_certificate_sd_jwt"
COURSE_MDOC = "app.foaap.course_certificate_mdoc"
COURSE_NAMESPACE = "app.foaap.course_certificate.1"
# Said in every demo PID, so nobody can take one for an identity document.
DEMO_AUTHORITY = "FOAAP demo issuer (not an identity document)"
CREDENTIALS = ("pid", "course")
FORMATS = {"pid": ("both",), "course": ("sd_jwt", "mdoc")}
FLOWS = ("pre-authorized_code", "authorization_code")


@dataclass(frozen=True)
class Persona:
    id: str
    name: str
    pid: dict[str, Any]
    course: dict[str, Any]


def load_personas(path: Path) -> dict[str, Persona]:
    """The fictional people of the demo, by id. Fixed data: the visitor picks one, never types one."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"{path}: an object of personas")
    personas = {}
    for key, entry in raw.items():
        if not (isinstance(key, str) and key.isascii() and key.isalnum() and key.islower() and len(key) <= 20):
            raise ValueError(f"{path}: persona ids are short lowercase letters and digits, not {key!r}")
        personas[key] = Persona(key, str(entry["name"]), dict(entry["pid"]), dict(entry["course"]))
    return personas


def configurations(credential: str, fmt: str, pid_configurations: tuple[str, ...]) -> list[str]:
    if credential == "pid":
        return list(pid_configurations)
    return [COURSE_SD_JWT if fmt == "sd_jwt" else COURSE_MDOC]


def subject(persona: Persona, credential: str, fmt: str, today: dt.date, pid_validity_days: int) -> dict[str, Any]:
    """The subject data of an offer for this persona. Dates are set from today, so the data never goes stale."""
    if credential == "pid":
        expiry = today + dt.timedelta(days=pid_validity_days)
        return {**persona.pid, "issuing_authority": DEMO_AUTHORITY, "date_of_expiry": expiry.isoformat()}
    completed = (today - dt.timedelta(days=3)).isoformat()
    data = {**persona.course, "date_of_completion": completed}
    if fmt == "mdoc":
        elements = {**data, "language_of_classes": ", ".join(data["language_of_classes"])}
        return {COURSE_NAMESPACE: elements}
    return data


# The fields the page shows on the face of each credential's card, of the person it is for.
CARD = {
    "pid": ("given_name", "family_name", "birthdate", "place_of_birth", "nationalities"),
    "course": (
        "achievement_title",
        "assessment_grade",
        "ects_credits",
        "level_of_learning_experience",
        "course_provider",
    ),
}


def card(persona: Persona, credential: str, today: dt.date, pid_validity_days: int) -> list[list[str]]:
    """The face of the credential's card: [claim name, value as text] for each field of CARD, as in the offer."""
    data = subject(persona, credential, "sd_jwt", today, pid_validity_days)
    return [[name, shown(data[name])] for name in CARD[credential] if name in data]


def step(
    progress: dict[str, Any] | None, signing_in: bool, offer_open: bool, revoked: bool, cancelled: bool = False
) -> str:
    """The step the page shows, from cunho's progress of the subject (None before a code-flow login):

    waiting -> signing_in -> connected -> held / released / refused -> issued -> stored, or cancelled, failed,
    deleted, revoked, closed, expired; rejected while the issuer refused the wallet's last credential request."""
    if progress is None:
        if cancelled:
            return "cancelled"
        if not offer_open:
            return "expired"  # a login abandoned on its screen ends with the offer (the second reviewer)
        return "signing_in" if signing_in else "waiting"
    state = progress["state"]
    configs = progress["configurations"]
    if state == "closed":
        return "revoked" if revoked else "closed"
    for review in ("held", "released", "refused"):
        if any(c["state"] == review for c in configs):
            return review
    if state == "issued":
        events = [c["notification"] for c in configs]
        if any(e == "credential_failure" for e in events):
            return "failed"
        if any(e == "credential_deleted" for e in events):
            return "deleted"
        if events and all(e == "credential_accepted" for e in events):
            return "stored"
        return "issued"
    if state == "redeemed":
        return "rejected" if progress.get("refusal") else "connected"
    if state == "offered":
        if progress.get("refusal"):
            return "token_rejected"  # refused at the token endpoint while the offer waits: not connected yet
        return "signing_in" if signing_in else "waiting"
    return "expired"
