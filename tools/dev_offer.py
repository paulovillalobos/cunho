"""Create a pre-authorized offer on a local cunho with a sample PID, and print the offer URI.

Usage: python tools/dev_offer.py ISSUER_URL ADMIN_TOKEN_FILE [--tx 6 | --code-flow] [--mdoc] [--course]
With --tx it prints JSON {"offer": ..., "tx_code": ...} (the format eudi-probe --offer-cmd accepts). With
--code-flow the offer is for the authorization code flow instead: it carries an issuer_state and no subject data,
since the login says who the person is. With --mdoc it offers the mdoc PID beside the SD-JWT VC one. With --course
it offers the demo's course certificate (demo/metadata/course) instead: the SD-JWT VC, or with --mdoc the mdoc
alone, since one subject cannot be both an SD-JWT VC's claims and an mdoc's namespaces.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

SAMPLE_PID: dict[str, object] = {
    "family_name": "Silva",
    "given_name": "Ana Maria",
    "birthdate": "1990-05-17",
    "place_of_birth": {"locality": "Porto", "country": "PT"},
    "nationalities": ["PT"],
    "issuing_authority": "Example Registry",
    "issuing_country": "PT",
    "date_of_expiry": "2031-11-04",
}


SAMPLE_COURSE: dict[str, object] = {
    "family_name": "Silva",
    "given_name": "Ana Maria",
    "achievement_title": "Introduction to the European Digital Identity Wallet",
    "language_of_classes": ["pt", "en"],
    "expected_study_time": "PT12H",
    "ects_credits": 1,
    "course_provider": "FOAAP Academy (demo)",
    "date_of_completion": "2026-11-02",
}
COURSE_NAMESPACE = "app.foaap.course_certificate.1"


def main(argv: list[str]) -> None:
    issuer, token_file = argv[0], Path(argv[1])
    tx = int(argv[argv.index("--tx") + 1]) if "--tx" in argv else None
    subject: dict[str, object]
    if "--course" in argv:
        if "--mdoc" in argv:
            configurations = ["app.foaap.course_certificate_mdoc"]
            elements = {**SAMPLE_COURSE, "language_of_classes": "pt, en"}
            subject = {COURSE_NAMESPACE: elements}
        else:
            configurations, subject = ["app.foaap.course_certificate_sd_jwt"], SAMPLE_COURSE
    else:
        configurations = ["eu.europa.ec.eudi.pid_vc_sd_jwt"]
        configurations += ["eu.europa.ec.eudi.pid_mdoc"] if "--mdoc" in argv else []
        subject = SAMPLE_PID
    body: dict[str, object] = {"credential_configuration_ids": configurations}
    if "--code-flow" in argv:
        body["grant"] = "authorization_code"
    else:
        body.update(subject=subject, tx_code_length=tx)
    response = httpx.post(
        f"{issuer}/admin/offers",
        json=body,
        headers={"Authorization": f"Bearer {token_file.read_text().strip()}"},
        verify=False,
    )
    if response.status_code != 201:
        raise SystemExit(f"the offer was refused: {response.status_code} {response.text}")
    made = response.json()
    if tx:
        print(json.dumps({"offer": made["offer_link"], "tx_code": made["tx_code"]}))
    else:
        print(made["offer_link"])


if __name__ == "__main__":
    main(sys.argv[1:])
