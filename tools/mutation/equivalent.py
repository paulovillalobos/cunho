"""Mutants that cannot change what cunho does, each with the reason. Keep this list short and true.

The mutation run fails when a listed mutant is killed (it was not equivalent after all) or no longer
exists (the code moved on), so an entry cannot outlive its reason.
"""

from __future__ import annotations

EQUIVALENT: dict[str, str] = {
    # M4 piece A
    "cose.py:verify1: flip: set(protected) <= KNOWN_HEADERS [0]": (
        "the protected labels equal KNOWN_HEADERS only when they include crit, which the same condition refuses "
        "first, so subset and proper subset refuse the same headers"
    ),
    # M3 piece C
    "revocation.py:_read: site: raise JoseError('the OCSP response does not hold exactly one answer')": (
        "cryptography's builder cannot make a response with two answers, and the library raises when such a "
        "response's fields are read, which _read turns into the same refusal"
    ),
    "revocation.py:FetchedRevocation._by_crl: drop: seen is not None in seen is not None and (newest is None or "
    "newest < seen)": (
        "seen is None only when no CRL in anything seen has been issued yet; then no CRL is in force either, so "
        "newest is None and the check refuses with the same words whichever way"
    ),
    "fetch.py:Fetcher._left: flip: left <= 0 [0]": (
        "with exactly no time left, going on hands the connection or the timer a zero budget, which fails at "
        "once, and the refusal names the time budget either way"
    ),
}
