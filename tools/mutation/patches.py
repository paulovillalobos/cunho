"""Hand-written mutants: semantic changes that no automatic rule in `mutate.py` produces.

Most come from the third M2 review's condition run (`condmut.py`, ids kept in the labels); the rest
break obligations added with its fixes. Each entry is (label, file under src/cunho, old text, new text).
The old text must occur exactly once in the file, or the run stops: a patch that no longer applies
has to be updated with the code, never dropped silently.
"""

from __future__ import annotations

PATCHES: list[tuple[str, str, str, str]] = [
    # oauth: DPoP, nonces, tx_code, stored rows
    (
        "O1 DPoP iat in the future accepted",
        "oauth.py",
        "abs(self._clock() - iat) > self._settings.dpop_iat_window",
        "self._clock() - iat > self._settings.dpop_iat_window",
    ),
    ("O2 DPoP jti cache lives 1 s", "oauth.py", "self._settings.dpop_iat_window * 2 + 5", "1"),
    (
        "O4 DPoP server nonce never expires",
        "oauth.py",
        "return 0 <= self._clock() - int(stamp) <= self._settings.dpop_iat_window * 5",
        "return True",
    ),
    (
        "O4b DPoP server nonce from the future accepted",
        "oauth.py",
        "return 0 <= self._clock() - int(stamp) <= self._settings.dpop_iat_window * 5",
        "return self._clock() - int(stamp) <= self._settings.dpop_iat_window * 5",
    ),
    ("O5 htu userinfo accepted", "oauth.py", 'if not parts.hostname or "@" in parts.netloc:', "if not parts.hostname:"),
    (
        "O6 htu port ignored",
        "oauth.py",
        'netloc = host if port in (None, default) else f"{host}:{port}"',
        "netloc = host",
    ),
    (
        "O7 htu scheme ignored",
        "oauth.py",
        "return f\"{parts.scheme.lower()}://{netloc}{parts.path or '/'}\"",
        "return f\"https://{netloc}{parts.path or '/'}\"",
    ),
    (
        "O7b htu host case kept",
        "oauth.py",
        "host = parts.hostname.lower()",
        "host = parts.netloc.rsplit(':', 1)[0] if port else parts.netloc",
    ),
    (
        "O8 last wrong tx_code no longer cancels the offer",
        "oauth.py",
        "if attempts >= self._settings.tx_code_max_attempts:",
        "if False:",
    ),
    (
        "O11 stored rows not checked against their MAC",
        "oauth.py",
        'if not same(keyring.mac(purpose, _record_text(key, record)), str(value.get("mac", ""))):',
        "if False:",
    ),
    (
        "O12 stored rows not checked against their own expiry",
        "oauth.py",
        "if not isinstance(expires, int) or expires <= now:",
        "if not isinstance(expires, int):",
    ),
    (
        "O13 MAC does not cover the row key",
        "oauth.py",
        'return json.dumps({"key": key, "record": record}',
        'return json.dumps({"record": record}',
    ),
    # proofs
    (
        "P4 key-proof iat in the future accepted",
        "proofs.py",
        "abs(self._clock() - iat) > self._settings.proof_iat_window",
        "self._clock() - iat > self._settings.proof_iat_window",
    ),
    (
        "P5 status cap takes the max of several key attestations",
        "proofs.py",
        "min(self.status_exp, int(exp))",
        "max(self.status_exp, int(exp))",
    ),
    (
        "P6 nonce inside a jwt-proof key attestation never consumed",
        "proofs.py",
        '            proven.nonces.add(str(claims["nonce"]))',
        "            pass",
    ),
    ("P7 c_nonce of proofs never consumed", "proofs.py", "        proven.nonces.add(str(value))", "        pass"),
    (
        "P8 CRLs not passed to path validation",
        "proofs.py",
        "revocation=self._trust.revocation(),",
        "revocation=None,",
    ),
    (
        "P9 a changed CRL file is not read again",
        "proofs.py",
        "            if stamp != self._stamp:",
        "            if False:",
    ),
    (
        "P10 a CRL file that no longer parses keeps the old CRLs",
        "proofs.py",
        "                    self._crls = []\n",
        "                    pass\n",
    ),
    # service: issuance, validity, revocation, vault
    (
        "S2 PID exp not capped by the key storage status period",
        "service.py",
        "for status_exp in (proven.status_exp, grant.client_status_exp):",
        "for status_exp in (grant.client_status_exp,):",
    ),
    ("S3 exp not capped by date_of_expiry", "service.py", "exp = min(exp, int(end_of_day))", "exp = exp"),
    ("S4 exp not coarsened", "service.py", "exp = exp // step * step", "exp = exp"),
    ("S5 nbf not coarsened", "service.py", "        nbf = now // step * step\n", "        nbf = now\n"),
    (
        "S7 vault not erased after the grant is used",
        "service.py",
        "            self.vault.erase(grant.subject_ref)\n        return",
        "            pass\n        return",
    ),
    (
        "S8 revocation counts decoys and already revoked slots",
        "service.py",
        "revoked = [ref for ref in refs if self.status.revocable(ref)]",
        "revoked = refs",
    ),
    (
        "S9 audit failure leaves issued slots live",
        "service.py",
        "            for ref in refs:\n                self.status.revoke(ref)\n            if transaction is None:\n",
        "            if transaction is None:\n",
    ),
    ("S11 issued batch sizes not counted", "service.py", "        self.status.note_batch(len(refs))\n", ""),
    (
        "S12 grant reference left out of credential.issued",
        "service.py",
        "                    grant=self._grant_ref(grant.offer_id),\n                    configuration_id=config_id,\n"
        "                    count=len(credentials),\n",
        "                    configuration_id=config_id,\n                    count=len(credentials),\n",
    ),
    (
        "S13 vault entry not bound to its offer",
        "service.py",
        "tx_code=length is not None,\n            )\n            self.vault.put(subject_ref, subject, "
        "window, offer_id)",
        "tx_code=length is not None,\n            )\n            self.vault.put(subject_ref, subject, window, '')",
    ),
    (
        "S14 issued rows written after the log transaction",
        "service.py",
        "                for key, ref in zip(keys, refs, strict=True):\n"
        "                    self.store.put(\n"
        '                        "issued",\n'
        '                        f"{grant.subject_ref}:{ref.list_id}:{ref.index}",\n'
        '                        {"list": ref.list_id, "idx": ref.index},\n'
        "                        max(exp - self.time(), 60),\n"
        "                    )\n"
        "                    watch = self._chain_watch(proven, grant, key) if chained else []\n"
        "                    if watch:\n"
        "                        # What revocation chaining checks again for"
        " this credential while it lives (LC_GEN-4).\n"
        "                        self.store.put(\n"
        '                            "chain",\n'
        '                            f"{grant.subject_ref}:{ref.list_id}:{ref.index}",\n'
        '                            {"watch": watch, "exp": exp, "ok": int(self.time())},\n'
        "                            max(exp - self.time(), 60),\n"
        "                        )\n"
        "                # As long as the subject's open row can live, for an offer or a login (the second reviewer).\n"
        '                self.store.put("subject-done",'
        ' f"{grant.subject_ref}:{config_id}", 1, self._subject_window())\n'
        "                # When, for GET /admin/offers/{subject_ref}: a review asked for later is newer than this"
        " issuance.\n"
        '                issued_at = f"{grant.subject_ref}:{config_id}"\n'
        '                self.store.put("subject-issued", issued_at, self.time(), self._subject_window())\n'
        "                self._keep_configs(grant.subject_ref)\n"
        "        except BaseException:\n"
        "            # Nothing was handed out: its slots never reach a wallet, and the claim is given back, so\n"
        "            # the offer is not live for a configuration it can no longer issue (review 6, N6-L4).\n"
        "            for ref in refs:\n"
        "                self.status.revoke(ref)\n"
        "            if transaction is None:\n"
        "                self._release_grant(grant, config_id, proven)\n"
        "            raise\n"
        "        self.status.note_batch(len(refs))\n",
        "                for key, ref in zip(keys, refs, strict=True):\n"
        "                    watch = self._chain_watch(proven, grant, key) if chained else []\n"
        "                    if watch:\n"
        "                        # What revocation chaining checks again for"
        " this credential while it lives (LC_GEN-4).\n"
        "                        self.store.put(\n"
        '                            "chain",\n'
        '                            f"{grant.subject_ref}:{ref.list_id}:{ref.index}",\n'
        '                            {"watch": watch, "exp": exp, "ok": int(self.time())},\n'
        "                            max(exp - self.time(), 60),\n"
        "                        )\n"
        "                # As long as the subject's open row can live, for an offer or a login (the second reviewer).\n"
        '                self.store.put("subject-done",'
        ' f"{grant.subject_ref}:{config_id}", 1, self._subject_window())\n'
        "                # When, for GET /admin/offers/{subject_ref}: a review asked for later is newer than this"
        " issuance.\n"
        '                issued_at = f"{grant.subject_ref}:{config_id}"\n'
        '                self.store.put("subject-issued", issued_at, self.time(), self._subject_window())\n'
        "                self._keep_configs(grant.subject_ref)\n"
        "        except BaseException:\n"
        "            # Nothing was handed out: its slots never reach a wallet, and the claim is given back, so\n"
        "            # the offer is not live for a configuration it can no longer issue (review 6, N6-L4).\n"
        "            for ref in refs:\n"
        "                self.status.revoke(ref)\n"
        "            if transaction is None:\n"
        "                self._release_grant(grant, config_id, proven)\n"
        "            raise\n"
        "        self.status.note_batch(len(refs))\n"
        "        for ref in refs:\n"
        "            self.store.put(\n"
        '                "issued",\n'
        '                f"{grant.subject_ref}:{ref.list_id}:{ref.index}",\n'
        '                {"list": ref.list_id, "idx": ref.index},\n'
        "                max(exp - self.time(), 60),\n"
        "            )\n",
    ),
    (
        "S15 revoking a subject leaves its live offer open",
        "service.py",
        "            self._close_subject(subject_ref)\n"
        "            self.vault.erase(subject_ref)\n"
        "            # Its credentials are revoked: nothing is left to chain, so their attestations' references go.",
        "            self.vault.erase(subject_ref)\n"
        "            # Its credentials are revoked: nothing is left to chain, so their attestations' references go.",
    ),
    (
        "S15b a revocation closes only a subject whose vault is still there (review 5, N5-M2)",
        "service.py",
        "            self._close_subject(subject_ref)\n"
        "            self.vault.erase(subject_ref)\n"
        "            # Its credentials are revoked: nothing is left to chain, so their attestations' references go.",
        '            if self.store.get("vault-key", subject_ref) is not None:\n'
        "                self._close_subject(subject_ref)\n"
        "            self.vault.erase(subject_ref)\n"
        "        if person:",
    ),
    (
        "S15c an offer counts as live while its vault entry is there",
        "service.py",
        '        configurations = self.store.get("subject-open", subject_ref)\n',
        '        return self.store.get("vault-key", subject_ref) is not None\n'
        '        configurations = self.store.get("subject-open", subject_ref)\n',
    ),
    (
        "S15d a configuration counts as issued once claimed",
        "service.py",
        '                self.store.put("subject-done", f"{grant.subject_ref}:{config_id}", '
        "1, self._subject_window())\n",
        "",
    ),
    (
        "S15e a subject revocation keeps the subject data",
        "service.py",
        "            self._close_subject(subject_ref)\n"
        "            self.vault.erase(subject_ref)\n"
        "            # Its credentials are revoked: nothing is left to chain, so their attestations' references go.",
        "            self._close_subject(subject_ref)\n"
        "            # Its credentials are revoked: nothing is left to chain, so their attestations' references go.",
    ),
    (
        "S16 a cancelled offer keeps its vault entry",
        "service.py",
        "            self.vault.erase(subject_ref)  #",
        "            pass  #",
    ),
    (
        "S17b the closed-subject mark lives only the token ttl (review 5, S8)",
        "service.py",
        '        self.store.put("subject-closed", subject_ref, 1, self._subject_window())',
        '        self.store.put("subject-closed", subject_ref, 1, self.settings.access_token_ttl)',
    ),
    (
        "S17 the closed-subject mark lives one second",
        "service.py",
        '        self.store.put("subject-closed", subject_ref, 1, self._subject_window())',
        '        self.store.put("subject-closed", subject_ref, 1, 1)',
    ),
    (
        "R1a slot revocation flips bits outside the log transaction",
        "service.py",
        "        with self._logged():\n"
        '            return {"revoked": self._revoke_slots(refs, reason, operator, None)}',
        '        return {"revoked": self._revoke_slots(refs, reason, operator, None)}',
    ),
    (
        "R1b subject revocation flips bits outside the log transaction",
        "service.py",
        "            with self._logged():\n"
        "                return self._revoke_subjects([subject_ref], reason, operator)",
        "            return self._revoke_subjects([subject_ref], reason, operator)",
    ),
    (
        "R1c person revocation flips bits outside the log transaction",
        "service.py",
        "            with self._logged():\n                subjects = [",
        "            if True:\n                subjects = [",
    ),
    # service: subject references and person handles (review 5)
    (
        "S20 a subject reference is not checked against its tag",
        "service.py",
        "        if len(raw) == 18 and same(",
        "        if len(raw) == 18 or same(",
    ),
    (
        "S21 a subject reference matched from its start only",
        "service.py",
        "        if not isinstance(subject_ref, str) or not SUBJECT_REF.fullmatch(subject_ref):",
        "        if not isinstance(subject_ref, str) or not SUBJECT_REF.match(subject_ref):",
    ),
    (
        "S22 an erasure says data was held whether or not it was",
        "service.py",
        "subject_ref=subject_ref, data_held=held)",
        "subject_ref=subject_ref, data_held=True)",
    ),
    (
        "S23 an erasure keeps the link to the person handle",
        "service.py",
        '                self.store.delete("person", f"{person}:{subject_ref}")\n',
        "",
    ),
    (
        "S24 the person handle is kept in the clear",
        "service.py",
        "self._link_person_ref(subject_ref, self._person_ref(person), ttl)",
        "self._link_person_ref(subject_ref, person, ttl)",
    ),
    (
        "S25 the person link lives only the offer window",
        "service.py",
        "        ttl += settings.timestamp_granularity\n",
        "        ttl = settings.offer_ttl + settings.access_token_ttl\n",
    ),
    # service: maintenance and the wall clock (review 4)
    (
        "W12 the background tick does not repair the anchor (review 5, N5-M1)",
        "service.py",
        "            self.audit.repair()\n",
        "            pass\n",
    ),
    (
        "W6 a WAL checkpoint that failed is not tried again",
        "service.py",
        "        if self._wal_dirty:\n            self._checkpoint()\n",
        "",
    ),
    # credentials: the SD-JWT VC formatter
    (
        "C1 _sd digests not sorted",
        "credentials.py",
        'return {"_sd": sorted(digests + _decoys())} if digests else {}',
        'return {"_sd": digests + _decoys()} if digests else {}',
    ),
    ("C2 no decoy digests", "credentials.py", "range(secrets.randbelow(DECOYS_MAX + 1))", "range(0)"),
    ("C3 constant disclosure salt", "credentials.py", "b64u(secrets.token_bytes(16))", 'b64u(b"\\x00" * 16)'),
    ("C4 wrong SD-JWT typ", "credentials.py", '"typ": "dc+sd-jwt"', '"typ": "vc+sd-jwt"'),
    (
        "C5 x5t#S256 wrong",
        "credentials.py",
        'header["x5t#S256"] = certificate_thumbprint_s256(signer)',
        'header["x5t#S256"] = "AAAA"',
    ),
    ("C6 array element digests not wrapped", "credentials.py", 'out.append({"...": digest})', "out.append(digest)"),
    # status
    (
        "T1 status bits MSB first",
        "status.py",
        "                        bits[index // 8] |= 1 << (index % 8)\n",
        "                        bits[index // 8] |= 1 << (7 - index % 8)\n",
    ),
    (
        "T1b a new list's decoy bits MSB first",
        "status.py",
        "bits[index // 8] |= 1 << (index % 8)  # the decoys",
        "bits[index // 8] |= 1 << (7 - index % 8)  # the decoys",
    ),
    (
        "T2 pending bits visible at once",
        "status.py",
        '                limit = f"{list_id}:{int(upto * 1000):016d}:~"\n',
        '                limit = f"{list_id}:~"\n',
    ),
    (
        "T3 scheduled bits never hidden",
        "status.py",
        "        self._show_at(list_id, index, at)\n",
        "        self._show_at(list_id, index, 0)\n",
    ),
    (
        "T4 raw DEFLATE instead of ZLIB",
        "status.py",
        "zlib.compress(bytes(bits), 9)",
        "zlib.compress(bytes(bits), 9)[2:-4]",
    ),
    ("T5 status token sub wrong", "status.py", 'uri = f"{self._settings.issuer_url}/status/{list_id}"', 'uri = "x"'),
    ("T6 status token ttl dropped", "status.py", '            "ttl": self._settings.status_token_ttl,\n', ""),
    (
        "T9 list never closes at the fill limit",
        "status.py",
        "if used >= self._size(list_id) * self._settings.status_list_fill_limit:",
        "if False:",
    ),
    (
        "T10 status token valid for years",
        "status.py",
        "exp = start + self._settings.status_token_lifetime",
        "exp = start + 10**8",
    ),
    (
        "T11 revoked bits all shown at once",
        "status.py",
        "at = 0.0 if now is None else now + _uniform(self._settings.status_revocation_jitter)",
        "at = 0.0 if now is None else now",
    ),
    (
        "T12 decoy clusters always of size one",
        "status.py",
        "for _ in range(min(_weighted(sizes), room)):",
        "for _ in range(min(1, room)):",
    ),
    (
        "T13 decoys of a cluster all shown at once",
        "status.py",
        "self._decoy(list_id, moment + _uniform(spread))",
        "self._decoy(list_id, moment)",
    ),
    (
        "T17 iat is the moment of signing, not of the publication (review 4, N4-M3)",
        "status.py",
        "else self._jwt(uri, start, exp, lst)",
        "else self._jwt(uri, int(self._clock()), exp, lst)",
    ),
    (
        "T18 concurrent polls each sign the list (review 5, N5-M3)",
        "status.py",
        "            build = self._builds.setdefault(list_id, threading.Lock())",
        "            build = threading.Lock()",
    ),
    (
        "T19 a publication reads every hidden bit",
        "status.py",
        '        if self._store.scan("status-pending", prefix, 1, limit):',
        '        if self._store.items("status-pending", prefix) or True:',
    ),
    (
        "T21 applied bits stay queued",
        "status.py",
        '                        self._store.delete("status-pending", key)\n',
        "",
    ),
    (
        "T22 a list takes the size of the current setting (review 5, N5-L4)",
        "status.py",
        "        size = self._sizes.get(list_id)\n",
        "        size = self._settings.status_list_size\n",
    ),
    (
        "T23 maintenance does not bring lists forward",
        "service.py",
        "        self.status.publish()\n",
        "",
    ),
    (
        "T20 a decoy schedule set far ahead is kept",
        "status.py",
        "        if stored > now + 2 * max(self._settings.maintenance_interval, DAY):",
        "        if False:",
    ),
    ("T15 one schedule for every list", "status.py", 'mark = f"scheduled_until:{list_id}"', 'mark = "scheduled_until"'),
    ("T16 decoy schedule ignores the rate", "status.py", "moment += _exponential(rate / mean)", "moment += 60"),
    # audit and vault
    (
        "A10 vault ciphertext not bound to subject and offer",
        "audit.py",
        'return f"{subject_ref}|{binding}".encode()',
        "return subject_ref.encode()",
    ),
    (
        "A11 anchor file replaced under an open handle goes unnoticed",
        "audit.py",
        "                if (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino):\n"
        "                    return self._fd",
        "                return self._fd",
    ),
    (
        "A12 catch-up anchors entries without their own time",
        "audit.py",
        '            backlog.append((previous, int(entry["time"]), _clock_of(entry)))',
        "            backlog.append((previous, 0, _clock_of(entry)))",
    ),
    (
        "A13 damage after the last line is never closed (review 5, N5-M1)",
        "audit.py",
        '        data = self._prefix + "".join(out).encode()',
        '        data = "".join(out).encode()',
    ),
    (
        "A14 bytes no line declares are skipped when read",
        "audit.py",
        '        if line.get("damage") != expected:',
        "        if False:",
    ),
    (
        "A14b a declaration does not bind the damaged bytes",
        "audit.py",
        '        if line.get("damage") != expected:',
        '        if (line.get("damage") or {}).get("bytes") != (expected or {}).get("bytes"):',
    ),
    (
        "A14c a valid line after a long run of bytes is taken for a line",
        "audit.py",
        "            line = self._valid(raw[:-1] if complete else raw) if whole else None",
        "            line = self._valid(raw[:-1] if complete else raw)",
    ),
    (
        "A15 missing anchor lines are not written before the next change",
        "audit.py",
        "            damage = anchor.write(backlog) or anchor.damaged()\n",
        "            damage = anchor.write([]) or anchor.damaged()\n",
    ),
    (
        "A16 a failed anchor write after the commit fails the request",
        "audit.py",
        "            self.anchor.write(self._pending)\n        except (OSError, AuditError) as exc:",
        "            self.anchor.write(self._pending)\n        except ZeroDivisionError as exc:",
    ),
    (
        "A17 verify takes no lock for its snapshot",
        "audit.py",
        "        with self._lock, self.anchor.locked() if self.anchor else _nothing():",
        "        with _nothing():",
    ),
    (
        "A18 verify reads anchor lines appended after its snapshot",
        "audit.py",
        "lines = self.anchor.lines(repaired, upto=size) if self.anchor else iter(())",
        "lines = self.anchor.lines(repaired) if self.anchor else iter(())",
    ),
    (
        "A19 an anchor repair is not logged",
        "audit.py",
        "            damage = anchor.write(backlog) or anchor.damaged()\n",
        "            damage = anchor.write(backlog) and None\n",
    ),
    # http layer
    (
        "AP2 error text not sanitised",
        "app.py",
        'return "".join(c if c in SAFE_TEXT else "?" for c in value[:limit])',
        "return value[:limit]",
    ),
    (
        "AP5 /status is not rate-limited (review 5, N5-M3)",
        "app.py",
        '        limit(request, "status")\n',
        "",
    ),
    (
        "AP6 /status reads the store on the event loop (review 5, N5-L3)",
        "app.py",
        '        token = await work(issuer.status_cwt if form == "cwt" else issuer.status_token, list_id)',
        '        token = (issuer.status_cwt if form == "cwt" else issuer.status_token)(list_id)',
    ),
    (
        "AP3 limiter table unbounded",
        "app.py",
        "                while len(self._hits) >= self._max_clients:\n"
        "                    self._hits.popitem(last=False)\n",
        "",
    ),
    (
        "AP4 limiter forgets the previous minute",
        "app.py",
        "allowed = count + previous * weight < self._per_minute",
        "allowed = count < self._per_minute",
    ),
    # store
    (
        "ST1 SQLite take not atomic across processes",
        "store.py",
        "    def take(self, ns: str, key: str) -> Any | None:\n"
        "        with self.atomic():\n            self._purge(ns, key)\n",
        "    def take(self, ns: str, key: str) -> Any | None:\n"
        "        with self._lock:\n            self._purge(ns, key)\n",
    ),
    ("ST2 secure_delete off", "store.py", '        self._db.execute("PRAGMA secure_delete=ON")\n', ""),
    (
        "ST3 WAL never checkpointed",
        "store.py",
        '                busy, _, _ = self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()',
        "                busy = 0",
    ),
    (
        "ST6 a checkpoint waits as long as any write",
        "store.py",
        '            self._db.execute(f"PRAGMA busy_timeout={CHECKPOINT_WAIT_MS}")\n',
        "",
    ),
    (
        "ST7 a checkpoint held by a reader counts as done",
        "store.py",
        "            return int(busy) == 0",
        "            return True",
    ),
    (
        "ST5 MemoryStore keeps half of a failed unit",
        "store.py",
        "                for key, entry in self._journal.items():\n",
        "                for key, entry in []:\n",
    ),
    (
        "ST4 MemoryStore.add not single-use",
        "store.py",
        "            if self._live(ns, key, purge=True) is not None:\n"
        "                return False\n"
        "            self._keep((ns, key))\n",
        "            self._keep((ns, key))\n",
    ),
    # metadata
    (
        "M1 ES384 and ES512 not published",
        "metadata.py",
        'spec["proof_signing_alg_values_supported"] = sorted(ALGORITHMS)',
        "pass",
    ),
    (
        "M2 attestation proof type not published",
        "metadata.py",
        'proofs["attestation"] = copy.deepcopy(proofs["jwt"])',
        "pass",
    ),
    # jose: parsing and certificate paths (review 4)
    (
        "J1 surrogate check skips member names",
        "jose.py",
        "            inside = [*item, *item.values()] if isinstance(item, dict) else item",
        "            inside = [*item.values()] if isinstance(item, dict) else item",
    ),
    (
        "J2 surrogate check stops at arrays",
        "jose.py",
        "        elif isinstance(item, dict | list):",
        "        elif isinstance(item, dict):",
    ),
    (
        "J7 JSON bytes in UTF-16 or UTF-32 accepted (review 5, N5-L11)",
        "jose.py",
        '        data = bytes(data).decode("utf-8")',
        "        data = bytes(data)",
    ),
    (
        "J8 the decoder's message, with the wallet's bytes, is echoed",
        "jose.py",
        '        raise JoseError("header or payload is not valid JSON") from exc',
        '        raise JoseError(f"header or payload is not valid JSON: {exc}") from exc',
    ),
    (
        "J9 1, yes and on are not true",
        "settings.py",
        'if value in ("true", "1", "yes", "on"):',
        'if value in ("true",):',
    ),
    ("J3 x5c certificates not read in full", "jose.py", "    for cert in chain:\n        _readable(cert)\n", ""),
    (
        "J4 only the first anchor holding the key is tried",
        "jose.py",
        "            problem = problem or exc\n            continue",
        "            raise",
    ),
    ("J5 CRL number ignored", "jose.py", "    return number, crl.last_update_utc", "    return 0, crl.last_update_utc"),
    (
        "J6 first usable CRL taken as the newest",
        "jose.py",
        "newest = max(usable, key=_crl_order)",
        "newest = usable[0]",
    ),
    # review 6: the anchor reader (N6-H1)
    (
        "R6A1 a line that repeats or goes back is read as the next one",
        "audit.py",
        '        if last is not None and line["seq"] <= last["seq"]:',
        "        if False:",
    ),
    (
        "R6A2 a line that repeats the last one is read as the next one",
        "audit.py",
        '        if last is not None and line["seq"] <= last["seq"]:',
        '        if last is not None and line["seq"] < last["seq"]:',
    ),
    (
        "R6A3 a worker reads on from where it stopped in a shorter anchor",
        "audit.py",
        "        if size < self._read.end:",
        "        if False:",
    ),
    (
        "R6A4 verify does not check the anchor as a writer does",
        "audit.py",
        "                backlog = self._unanchored(self.anchor)\n",
        "                backlog = []\n",
    ),
    (
        "R6A5 verify passes over entries not anchored yet",
        "audit.py",
        "        if backlog:\n            return False, (",
        "        if False:\n            return False, (",
    ),
    (
        "R6A6 a line missing only its newline is taken for damage",
        "audit.py",
        "                at.trailing = line  # complete apart from its newline, so at the very end",
        "                pass",
    ),
    (
        "R6A7 a declaration leaves out the newline that closes the damage",
        "audit.py",
        '            digest.update(b"\\n")\n',
        "",
    ),
    (
        "R6A8 a worker's own write does not move where it reads on from",
        "audit.py",
        "        self._read = _Read(end, last)\n",
        "",
    ),
    (
        "X17 verify goes on from a checkpoint past the head it read (review 6, N6-L1)",
        "audit.py",
        "                if moved[0].seq > upto:\n                    return None",
        "                if False:\n                    return None",
    ),
    # review 6: the clock watch, pruning and the moments of revocations (N6-M1, N6-M3)
    (
        "R6C11 without evidence a revocation is laid from the wall clock",
        "status.py",
        "            at = 0.0 if now is None else now + _uniform(self._settings.status_revocation_jitter)",
        "            at = self._clock() if now is None else now + _uniform(self._settings.status_revocation_jitter)",
    ),
    # review 6: the schema version and the upgrade (N6-M2)
    (
        "R6U1 the upgrade leaves the old queue rows as they were",
        "schema.py",
        '            store.delete("status-pending", pending)\n',
        "",
    ),
    (
        "R6U2 the upgrade drops the bits still hidden",
        "schema.py",
        "            if float(at) > now:",
        "            if False:",
    ),
    (
        "R6U3 the upgrade shows the bits still hidden",
        "schema.py",
        "            if value == REVOKED and index not in hidden:",
        "            if value == REVOKED:",
    ),
    (
        "R6U4 the upgrade takes the setting for a list that stored its size",
        "schema.py",
        '        size = meta.get("size") if isinstance(meta, dict) else None',
        "        size = None",
    ),
    (
        "R6U5 the upgrade records no subject reference from before the tag",
        "schema.py",
        "        if not handed_out(reference):",
        "        if False:",
    ),
    (
        "R6U6 the upgrade leaves the offers made before it not live",
        "schema.py",
        '            store.put("subject-open", reference, list(configuration_ids), window)\n',
        "            pass\n",
    ),
    (
        "R6U7 every start upgrades again",
        "schema.py",
        "        if version == SCHEMA:\n            return False",
        "        if False:\n            return False",
    ),
    (
        "R6U8 a new store is taken for one written before the version",
        "schema.py",
        "        earlier = not store.empty()",
        "        earlier = True",
    ),
    (
        "R6U9 a subject reference from before the tag is refused",
        "service.py",
        '        return self.store.get("subject-legacy", subject_ref) is not None',
        "        return False",
    ),
    # review 6: erasure, refused claims, and the round-5 mutants only slow suites killed (N6-L1, L3, L4)
    (
        "R6S1 an erasure leaves the subject open",
        "service.py",
        "            self._close_subject(subject_ref)\n"
        "            self.vault.erase(subject_ref)\n"
        "            if isinstance(person, str):",
        "            self.vault.erase(subject_ref)\n            if isinstance(person, str):",
    ),
    (
        "R6S2 a configuration is claimed apart from its keys",
        "service.py",
        "        with self.store.atomic():\n            now = self.time()\n",
        "        if True:\n            now = self.time()\n",
    ),
    (
        "R6S3 a failed issuance keeps its claim",
        "service.py",
        "            if transaction is None:\n"
        "                self._release_grant(grant, config_id, proven)\n            raise",
        "            raise",
    ),
    (
        "R6S4 a failed issuance keeps the claim of its keys",
        "service.py",
        '                self.store.delete("subject-key", self._key_ref(grant.subject_ref, key))',
        "                pass",
    ),
    (
        "R6S5 a failed issuance keeps the claim of its configuration",
        "service.py",
        '            self.store.delete("grant-config", f"{grant.grant_id}:{config_id}")\n',
        "",
    ),
    (
        "X11 an issued configuration is recorded for a second",
        "service.py",
        'self.store.put("subject-done", f"{grant.subject_ref}:{config_id}", 1, self._subject_window())',
        'self.store.put("subject-done", f"{grant.subject_ref}:{config_id}", 1, 1)',
    ),
    (
        "X15 what an offer can yield lives only the offer ttl",
        "service.py",
        'self.store.put("subject-open", subject_ref, list(ids), window)',
        'self.store.put("subject-open", subject_ref, list(ids), self.settings.offer_ttl)',
    ),
    # review 7: one time base, the clock watch's (M1, M2, the second reviewer's CX-4), the earlier clock mutants
    # brought over to it, and pruning that removes only what verifies (CX-1)
    (
        "W1 maintenance does not read the clock",
        "service.py",
        "        elif not watch.steady():\n",
        "        elif False:\n",
    ),
    (
        "W2 the background tick does not read the clock",
        "service.py",
        "        self.clock_watch.steady()\n        now = self.clock_watch.now()\n",
        "        now = self.clock_watch.now()\n",
    ),
    (
        "W3 a time that went back, by a forced run, stalls maintenance",
        "service.py",
        "not 0 <= now - self._last_maintenance",
        "not now - self._last_maintenance",
    ),
    (
        "W4 a forced run does not vouch for the clock",
        "service.py",
        "                base = watch.trust(self.clock())\n",
        "                base = None\n",
    ),
    (
        "W5 the base is not kept in the store",
        "service.py",
        '        self._store.put("maintenance", f"clock:{base.boot}", row, None)',
        "        pass",
    ),
    (
        "W7 the time follows the wall clock, whatever the host clock says (review 7, M2)",
        "service.py",
        "        return self._expected(self._current())",
        "        return self._clock() if self._expected(self._current()) is not None else None",
    ),
    (
        "W8 a new boot is trusted at once without asking the kernel",
        "service.py",
        "reading >= max(seen, last.time) and synced is True:",
        "reading >= max(seen, last.time):",
    ),
    (
        "W9 a restart does not read the host clock kept with the base",
        "service.py",
        "                return candidate\n",
        "                return Base(candidate.time, 0.0, candidate.boot)\n",
    ),
    (
        "W10 entry times are the reading, not the time (review 5, N5-L8)",
        "audit.py",
        '            "time": reading if now is None else int(now),',
        '            "time": reading,',
    ),
    (
        "R7A9 an entry keeps no reading far from its time",
        "audit.py",
        "        if now is not None and abs(reading - now) > CLOCK_TOLERANCE:",
        "        if False:",
    ),
    (
        "W11 the expected time ignores the host clock",
        "service.py",
        "        return base.time + (self._host.elapsed() if elapsed is None else elapsed) - base.elapsed",
        "        return base.time",
    ),
    (
        "R7C1 the wall clock within the tolerance is taken as it reads",
        "service.py",
        "        return self._expected(self._current())",
        "        expected = self._expected(self._current())\n"
        "        reading = self._clock()\n"
        "        return None if expected is None else min(max(reading, expected - CLOCK_TOLERANCE), expected + 120)",
    ),
    (
        "R7C2 the tolerance that tells a reading off from one right is ten times wider (review 7, L4 S24)",
        "service.py",
        "                self._behind = reading < expected - CLOCK_TOLERANCE",
        "                self._behind = reading < expected - 10 * CLOCK_TOLERANCE",
    ),
    (
        "R7C3 a base from another boot is gone by",
        "service.py",
        "        if base is None or base.boot != self._boot():",
        "        if base is None:",
    ),
    (
        "R7C4 a reading on the same boot lays a new base, so a creeping clock walks the time (review 7, M2)",
        "service.py",
        '                        ", and audit pruning waits" if self._behind else "",\n                    )\n'
        "                return True",
        '                        ", and audit pruning waits" if self._behind else "",\n                    )\n'
        "                self._lay(reading, elapsed)\n                return True",
    ),
    (
        "R7C5 pruning does not wait while the wall clock reads behind",
        "service.py",
        "and expected is not None and not self._behind and expected",
        "and expected is not None and expected",
    ),
    (
        "R7C6 pruning does not wait an interval after a new base (review 6, N6-M3)",
        "service.py",
        " and expected - base.time >= self._settle",
        "",
    ),
    (
        "R7C7 a new boot is trusted at once behind the latest time seen (review 7, L4 S27)",
        "service.py",
        "and reading >= max(seen, last.time) and synced is True:",
        "and synced is True:",
    ),
    (
        "R7C8 the latest time seen is not kept",
        "service.py",
        '                self._store.put("maintenance", "seen", {"time": latest, '
        '"tag": self._tag("clock-seen", latest)}, None)\n',
        "",
    ),
    (
        "R7C9 a reading on a new boot that does not keep pace with the host clock keeps its wait",
        "service.py",
        "            if new is None or abs((reading - new[0]) - (elapsed - new[1])) > CLOCK_TOLERANCE:",
        "            if new is None:",
    ),
    (
        "R8C5 a worker goes by the base it read last, not the one in the store (CX-13)",
        "service.py",
        "        return self._adopt(self._stored())",
        "        return self._kept[1]",
    ),
    (
        "R8C6 a worker keeps the first base it read, whatever the row says later (CX-13)",
        "service.py",
        "        if stored == kept[0]:",
        "        if kept[0] is not None:",
    ),
    (
        "R7C11 a worker reads the clock first at its first tick",
        "service.py",
        "        self.clock_watch.steady()  # the first reading: a worker goes by the time from its first request\n",
        "",
    ),
    (
        "R8C1 the base takes the host clock when it is laid, not with the wall-clock reading (CX-5)",
        "service.py",
        "        base = Base(float(now), float(elapsed), boot)",
        "        base = Base(float(now), self._host.elapsed(), boot)",
    ),
    (
        "R8C2 workers lay the base outside one store transaction (CX-6)",
        "service.py",
        "        with self._store.atomic(), self._lock:\n            # Whether any boot",
        "        with self._lock:\n            # Whether any boot",
    ),
    (
        "R8C3 a clock base whose MAC does not verify is gone by (the second reviewer)",
        "service.py",
        "            if candidate is not None and same(\n"
        '                self._tag("clock-base", candidate.time, candidate.elapsed, candidate.boot), '
        'stored["tag"]\n'
        "            ):",
        "            if candidate is not None:",
    ),
    (
        "R8C4 a latest time seen whose MAC does not verify is gone by (CX-12)",
        "service.py",
        '            if seen is not None and same(self._tag("clock-seen", seen), stored["tag"]):',
        "            if seen is not None:",
    ),
    (
        "R8S1 a SQLite sweep goes by the cutoff read before the transaction (CX-15)",
        "store.py",
        "                cutoff = min(now, self._clock())  # read inside the transaction, "
        "as every other expiry (CX-15)",
        "                cutoff = now",
    ),
    (
        "R8S2 a memory sweep goes by the cutoff read before it (CX-15)",
        "store.py",
        "            cutoff = min(now, self._clock())\n            expired",
        "            cutoff = now\n            expired",
    ),
    (
        "R8A1 a cached status token is answered on the event loop (CX-14)",
        "app.py",
        '        token = await work(issuer.status_cwt if form == "cwt" else issuer.status_token, list_id)',
        "        token = issuer.status.cached(list_id, form) or await work(\n"
        '            issuer.status_cwt if form == "cwt" else issuer.status_token, list_id\n'
        "        )",
    ),
    (
        "R8A2 a refused admin request is counted on the event loop (CX-14)",
        "app.py",
        "            await work(  # it counts by the time, which reads the store (CX-14)\n"
        "                issuer.admin_refused,\n",
        "            (lambda *a: issuer.admin_refused(*a))(  # on the event loop\n",
    ),
    (
        "R8P1 a pruning batch goes by the time read before it (CX-16)",
        "audit.py",
        "                at = min(now, self._time())",
        "                at = now",
    ),
    (
        "R8P2 a pruning batch does not ask again whether it may go on (CX-16)",
        "audit.py",
        "                if still is not None and not still():",
        "                if False:",
    ),
    (
        "R8P3 maintenance pruning does not ask the clock watch again (CX-16)",
        "service.py",
        "            still = None if force else self.clock_watch.settled",
        "            still = None",
    ),
    (
        "R8R1 a clock base laid before the floor on its boot is gone by (CX-17)",
        "service.py",
        "        if base is not None and self._before(base):",
        "        if False:",
    ),
    (
        "R8R4 a forced run's anchor line does not name its base (CX-17)",
        "audit.py",
        '        self._pending.append((Mark(entry["seq"], entry["mac"]), entry["time"], _clock_of(entry)))',
        '        self._pending.append((Mark(entry["seq"], entry["mac"]), entry["time"], None))',
    ),
    (
        "R8R5 a forced run's anchor line written late does not name its base (CX-17)",
        "audit.py",
        '            backlog.append((previous, int(entry["time"]), _clock_of(entry)))',
        '            backlog.append((previous, int(entry["time"]), None))',
    ),
    (
        "R8R6 reading the anchor does not keep the newest base it names (CX-17)",
        "audit.py",
        '                    at.clock = line["clock"]',
        "                    pass",
    ),
    (
        "R8R2 a reading of the time does not ask the anchor for the floor (CX-18)",
        "service.py",
        "        self._raise_floor()\n        kept = self._kept",
        "        kept = self._kept",
    ),
    (
        "R8U1 a base laid in a transaction that rolls back leaves the floor it raised (CX-20, CX-30)",
        "service.py",
        "        self._store.on_rollback(lambda: self._put_back(saved))\n",
        "",
    ),
    (
        "R8U2 a SQLite rollback does not undo what was asked (CX-30)",
        "store.py",
        '                        self._db.execute("ROLLBACK")\n'
        "                finally:\n"
        "                    for undo in reversed(self._undo):\n                        undo()\n",
        '                        self._db.execute("ROLLBACK")\n                finally:\n                    pass\n',
    ),
    (
        "R8U3 a memory store's rollback does not undo what was asked (CX-30)",
        "store.py",
        "                        self._data[key] = entry\n                for undo in reversed(self._undo):\n"
        "                    undo()\n",
        "                        self._data[key] = entry\n",
    ),
    (
        "R8T1 laying moments again goes by the time read before its transaction (CX-21)",
        "status.py",
        "        while True:\n            with self._store.atomic():\n                now = self.now()\n",
        "        first = self.now()\n        while True:\n"
        "            with self._store.atomic():\n                now = first\n",
    ),
    (
        "R8T2 bits come due by a cutoff read before their transaction (CX-23)",
        "status.py",
        "                upto = min(upto, self._publication()[1])\n",
        "",
    ),
    (
        "R8R11 a line that cannot be tagged breaks the reader (CX-22)",
        "audit.py",
        "        except (ValueError, UnicodeError, TypeError, RecursionError):\n"
        "            return None\n        return dict(line)",
        "        except (ValueError,):\n            return None\n        return dict(line)",
    ),
    (
        "R8R12 the clock reader fails with the anchor (CX-22)",
        "audit.py",
        "            except Exception as exc:  # noqa: BLE001 - the time must not fail with the anchor (CX-22)",
        "            except (OSError, AuditError) as exc:",
    ),
    (
        "R8S3 a SQLite row's expiry is stamped before its write transaction (CX-24)",
        "store.py",
        "        with self.atomic() if ttl is not None else self._lock:",
        "        with self._lock:",
    ),
    (
        "R8T3 decoys are scheduled by the time read before their transaction (CX-25)",
        "status.py",
        "        with self._store.atomic():\n"
        "            # Read inside the transaction, as every expiry is: a forced run in another worker may move the "
        "time\n"
        "            # meanwhile, and decoys laid by the time before would come due together (the second reviewer, "
        "CX-25).\n"
        "            now = self.now()\n",
        "        first = self.now()\n        with self._store.atomic():\n            now = first\n",
    ),
    (
        "R8V1 a claim does not check its token again (CX-26)",
        "service.py",
        "                now < grant.expires,\n",
        "                True,\n",
    ),
    (
        "R8V2 a clock number too large for a float raises (CX-27)",
        "service.py",
        "        return float(value)\n    except OverflowError:\n        return None\n",
        "        return float(value)\n    except ZeroDivisionError:\n        return None\n",
    ),
    (
        "R8V3 a claim's marker lives for the lifetime configured now (CX-28)",
        "service.py",
        "            ttl = grant.expires - now\n",
        "            ttl = self.settings.access_token_ttl\n",
    ),
    (
        "R8W1 an access token's expiry is read before the transaction that stores it (CX-29)",
        "oauth.py",
        "        with self._store.atomic():\n            record = {",
        "        if True:\n            record = {",
    ),
    (
        "R8W2 a c_nonce's time is read before the transaction that stores it (CX-29)",
        "oauth.py",
        "        with self._store.atomic():  # the time stored is read in the transaction that stores it (CX-29)",
        "        if True:",
    ),
    (
        "R8W3 a revocation's moment is read before its transaction (CX-29)",
        "status.py",
        "        with self._store.atomic():\n            now = self.now()\n            if now is None:\n"
        '                security_log.warning("the clock watch cannot vouch for the clock yet: a revocation shows '
        'at once")\n',
        "        now = self.now()\n        with self._store.atomic():\n",
    ),
    (
        "R8R10 a forced run is not logged (CX-17)",
        "service.py",
        '                    self.audit.append(CLOCK_TRUSTED, "cunho", boot=base.boot, elapsed=base.elapsed, '
        "time=base.time)",
        "                    pass",
    ),
    (
        "R7S2 sweeping goes by the wall clock",
        "service.py",
        "        return self.store.sweep(now)",
        "        return self.store.sweep(self.clock())",
    ),
    (
        "R7S10 the store keeps going by the wall clock it was built with",
        "service.py",
        "        self.store.go_by(self.time)\n",
        "",
    ),
    (
        "R7S11 offers go by the wall clock",
        "service.py",
        "        self.offers = Offers(settings, self.store, self.keyring, self.time)",
        "        self.offers = Offers(settings, self.store, self.keyring, clock)",
    ),
    (
        "R7S12 DPoP proofs go by the wall clock",
        "service.py",
        "        self.dpop = Dpop(settings, self.store, self.nonces, self.time)",
        "        self.dpop = Dpop(settings, self.store, self.nonces, clock)",
    ),
    (
        "R7S13 key proofs and attestations go by the wall clock",
        "service.py",
        "ProofVerifier(settings, self.nonces, self.trust, self.time, self.wallet_status)",
        "ProofVerifier(settings, self.nonces, self.trust, clock, self.wallet_status)",
    ),
    (
        "R7S14 a credential's validity goes by the wall clock",
        "service.py",
        "        step = self.settings.timestamp_granularity\n        now = int(self.time())",
        "        step = self.settings.timestamp_granularity\n        now = int(self.clock())",
    ),
    (
        "R7S15 the time is the wall clock whatever the watch says",
        "service.py",
        "        return self.clock() if now is None else now",
        "        return self.clock()",
    ),
    (
        "R7S4 a subject revocation finds issued records by the wall clock (the pre-check's note)",
        "service.py",
        '            issued = self.store.items("issued", f"{subject_ref}:", at=at)',
        '            issued = self.store.items("issued", f"{subject_ref}:")',
    ),
    (
        "R7S5 without a time a subject revocation finds issued records by the wall clock",
        "service.py",
        "every record still kept counts.\n        now = self.clock_watch.now()\n"
        "        at = -math.inf if now is None else now",
        "every record still kept counts.\n        now = self.clock_watch.now()\n        at = now",
    ),
    (
        "S10 vault erased after the first configuration of a multi-configuration grant",
        "service.py",
        'done = all(self.store.get("subject-done"',
        'done = any(self.store.get("subject-done"',
    ),
    (
        "R7S6 the vault is erased once every configuration is claimed (review 7, L5; the second reviewer's CX-3)",
        "service.py",
        'self.store.get("subject-done", f"{grant.subject_ref}:{c}") for c in grant.configuration_ids',
        'self.store.get("grant-config", f"{grant.grant_id}:{c}") for c in grant.configuration_ids',
    ),
    (
        "R7S7 pruning goes by the wall clock",
        "service.py",
        "            return self.audit.prune_before(now - self.settings.audit_retention_days * DAY, "
        "now=now, still=still)",
        "            return self.audit.prune_before(self.clock() - self.settings.audit_retention_days * DAY, "
        "still=still)",
    ),
    (
        "R7S8 the upgrade is not logged (review 7, L3)",
        "service.py",
        '                    self.audit.append("store.upgraded", "cunho", schema=schema.SCHEMA)\n',
        "",
    ),
    (
        "R7S16 every start takes the log for the upgrade, so a log that fails its checks stops cunho starting",
        "service.py",
        '        if self.store.get("meta", "schema") != schema.SCHEMA:\n',
        "        if True:\n",
    ),
    (
        "R7S9 an offer from before the upgrade is live for every configuration in the metadata",
        "service.py",
        "list(self.configs.issuable())",
        "list(self.configs.all)",
    ),
    (
        "R7T1 lists are published by the wall clock (review 7, M1)",
        "status.py",
        "        epoch = int(now // self._interval)",
        "        epoch = int(self._clock() // self._interval)",
    ),
    (
        "R7T2 without a time every bit due by the wall clock is published",
        "status.py",
        "            return (int(self._clock() // self._interval), False), 0.0",
        "            return (int(self._clock() // self._interval), False), self._clock()",
    ),
    (
        "R6C8 a revocation goes by the wall clock, not the clock watch",
        "status.py",
        "            now = self.now()\n            if now is None:\n                security_log.warning(",
        "            now = self._clock()\n            if now is None:\n                security_log.warning(",
    ),
    (
        "R7T3 decoys are scheduled by the wall clock",
        "status.py",
        "            now = self.now()\n            if now is None:\n                return 0\n",
        "            now = self._clock()\n",
    ),
    (
        "R7T4 a moment no clock that read right could lay stays in the queue",
        "status.py",
        "            self._relay(list_id)\n",
        "            pass\n",
    ),
    (
        "R7T5 moments beyond the jitter are laid again, the decoy schedule among them",
        "status.py",
        "now + 2 * settings.maintenance_interval + settings.status_revocation_jitter + CLOCK_TOLERANCE",
        "now + settings.status_revocation_jitter",
    ),
    (
        "T8 a cached token outlives its publication",
        "status.py",
        "        return entry[1] if entry is not None and entry[0] == self._publication()[0] else None",
        "        return entry[1] if entry is not None else None",
    ),
    (
        "T14 a new list waits for maintenance for its decoys",
        "status.py",
        "            if now is not None:\n                self._schedule(list_id, now)\n",
        "",
    ),
    (
        "R7A1 pruning does not check an entry's MAC (the second reviewer's CX-1)",
        "audit.py",
        '        return entry["prev"] == previous.mac and self._verifies(entry)',
        '        return entry["prev"] == previous.mac',
    ),
    (
        "R7A2 pruning does not check an entry follows the one before it",
        "audit.py",
        '        return entry["prev"] == previous.mac and self._verifies(entry)',
        "        return self._verifies(entry)",
    ),
    (
        "R7A4 pruning checks an entry's shape only, as before",
        "audit.py",
        "                    if not self._follows(entry, previous):",
        "                    if not _shaped(entry, seq=int, mac=str, time=int):",
    ),
    (
        "R7A5 pruning chains from the genesis, whatever the checkpoint",
        "audit.py",
        "                previous = checkpoint[0] if checkpoint is not None else Mark(0, GENESIS)",
        "                previous = Mark(0, GENESIS)",
    ),
    (
        "R7A6 an entry dated ahead is measured by the wall clock",
        "audit.py",
        '                    if entry["time"] > at + FUTURE_SLACK:',
        '                    if entry["time"] > self._clock() + FUTURE_SLACK:',
    ),
    (
        "R7A8 verify measures the checkpoint's age by the wall clock",
        "audit.py",
        "            if start[1] > self._time() - self._retention:",
        "            if start[1] > self._clock() - self._retention:",
    ),
    (
        "R7P1 each certificate's policies are checked on their own (the second reviewer's CX-2)",
        "jose.py",
        "            valid &= names\n",
        "            valid = set(policies) & names or valid\n",
    ),
    (
        "R7P2 the leaf's policy is checked against the deployment's alone",
        "jose.py",
        "    if not valid & _policies(chain[0]):",
        "    if not policies & _policies(chain[0]):",
    ),
    (
        "R7L1 the credential endpoint is not rate-limited (review 7, L7)",
        "app.py",
        '(review 7, L7)."""\n        limit(request, "credential")\n',
        '(review 7, L7)."""\n',
    ),
    (
        "R7O1 the DPoP replay cache lives only the iat window (review 7, L4 S32)",
        "oauth.py",
        "self._settings.dpop_iat_window * 2 + 5",
        "self._settings.dpop_iat_window",
    ),
    (
        "R7R1 an implements function does not report that it ran (registry: META.PREFERRED_STATUS_PERIODS)",
        "rules/__init__.py",
        "            for observe in reached:\n                observe(rules)\n",
        "",
    ),
    # M3 piece E: the authorization code flow and wallet attestation (authorize.py, client_auth.py, settings.py)
    (
        "E1 an authorization code lives 61 s",
        "authorize.py",
        "ttl = self._settings.code_ttl\n",
        "ttl = self._settings.code_ttl + 1\n",
    ),
    (
        "E2 a request_uri lives 600 s",
        "settings.py",
        "MAX_PAR_TTL = 599\n",
        "MAX_PAR_TTL = 600\n",
    ),
    ("E3 the attestation PoP replay cache lives 1 s", "client_auth.py", "window + FUTURE_SKEW + 5", "1"),
    (
        "E4 the redirect URI compared after normalisation",
        "authorize.py",
        "            value in allowed,\n",
        "            str(value).lower().rstrip('/') in {a.lower().rstrip('/') for a in allowed},\n",
    ),
    (
        "E5 the PKCE method ignored",
        "authorize.py",
        '            method == "S256",\n',
        '            method in ("S256", "plain", None),\n',
    ),
    (
        "E6 a reused code does not revoke what the first use yielded",
        "authorize.py",
        '            self._on_code_reuse(reused["subject_ref"], reused["token"], reused["refresh"])\n',
        "            pass\n",
    ),
    (
        "E7 an issuer_state is not consumed",
        "authorize.py",
        'self._store.take("issuer-state", key)',
        'self._store.get("issuer-state", key)',
    ),
    (
        "E8 a request_uri is not bound to the client that pushed it",
        "authorize.py",
        '            same(str(client_id), pushed["client"]),\n',
        "            True,\n",
    ),
    (
        "E9 the instance key is not compared at the token endpoint",
        "authorize.py",
        'same(identity.sub, row["client"]) and same(identity.cnf_jkt, row["cnf"])',
        'same(identity.sub, row["client"])',
    ),
    (
        "E10 the code is not bound to the DPoP key of PAR",
        "authorize.py",
        'row["dpop_jkt"] is None or same(jkt, row["dpop_jkt"])',
        "True",
    ),
    (
        "E11 the PoP iat window is open to the past",
        "client_auth.py",
        "iat > now + FUTURE_SKEW or iat < now - window",
        "iat > now + FUTURE_SKEW",
    ),
    (
        "E12 the code exchange reads the time before the transaction that stores the token",
        "authorize.py",
        "        with self._store.atomic():\n            taken = None\n",
        "        if True:\n            taken = None\n",
    ),
    (
        "E13 the login state outlives its login",
        "authorize.py",
        "            ttl = self._settings.login_ttl\n            record = {**{k: v for k, v in pushed.items()",
        "            ttl = self._settings.login_ttl * 10\n            record = {**{k: v for k, v in pushed.items()",
    ),
    (
        "E14 the wallet attestation's status period does not cap validity",
        "service.py",
        "for status_exp in (proven.status_exp, grant.client_status_exp):",
        "for status_exp in (proven.status_exp,):",
    ),
    (
        "E15 a login's vault entry not bound to its offer",
        "service.py",
        'flow=CODE_GRANT,\n                **({"review": True} if review else {}),\n            )\n'
        "            self.vault.put(subject_ref, subject, window, offer_id)",
        'flow=CODE_GRANT,\n                **({"review": True} if review else {}),\n            )\n'
        "            self.vault.put(subject_ref, subject, window, '')",
    ),
    (
        "E16 wallet attestations go by the wall clock",
        "service.py",
        "ClientAuth(settings, self.store, self.trust, self.time, self.wallet_status)",
        "ClientAuth(settings, self.store, self.trust, clock, self.wallet_status)",
    ),
    (
        "E17 a reused code leaves its subject open",
        "service.py",
        'cause="authorization_code_reused")\n            self._close_subject(subject_ref)\n',
        'cause="authorization_code_reused")\n',
    ),
    (
        "E18 the token request's attestation does not cap validity",
        "authorize.py",
        '_earlier(taken["client_status_exp"], identity.status_exp)',
        'taken["client_status_exp"]',
    ),
    (
        "E19 a spent code forgets the DPoP key it was redeemed with",
        "authorize.py",
        '"dpop_jkt": jkt,\n                    "token": token_key',
        '"dpop_jkt": taken["dpop_jkt"],\n                    "token": token_key',
    ),
    (
        "E20 login_state alone collects the code",
        "authorize.py",
        'isinstance(completion, str) and same(_hash(completion), done["completion"])',
        "True",
    ),
    (
        "E21 the PoP's exp ignored",
        "client_auth.py",
        "if exp is not None and (not is_number(exp) or exp <= now):",
        "if False:",
    ),
    (
        "E22 a key proof's iss not compared with the client",
        "proofs.py",
        'if "iss" in claims and claims["iss"] != client:',
        "if False:",
    ),
    # M3 piece F: refresh tokens and re-issuance (authorize.py, service.py)
    (
        "F1 a refresh ignores the closed mark",
        "authorize.py",
        '            self._store.get("subject-closed", row["subject_ref"]) is None,\n'
        '            "VCI.TOKEN.INVALID_GRANT",\n'
        '            "invalid_grant",\n'
        '            "this login\'s subject was revoked or erased",\n'
        "        )  # checked again in the issuance transaction, as for every token",
        "            True,\n"
        '            "VCI.TOKEN.INVALID_GRANT",\n'
        '            "invalid_grant",\n'
        '            "this login\'s subject was revoked or erased",\n'
        "        )  # checked again in the issuance transaction, as for every token",
    ),
    (
        "F3 a refresh token not bound to the instance key",
        "authorize.py",
        '            same(identity.cnf_jkt, row["cnf"]),\n',
        "            True,\n",
    ),
    (
        "F4 a refresh token not bound to the wallet solution",
        "authorize.py",
        'same(identity.sub, row["client"]),',
        "True,",
    ),
    (
        "F5 the vault is erased though a refresh token lives",
        "service.py",
        'if done and self.store.get("subject-refresh", grant.subject_ref) is None:',
        "if done:",
    ),
    (
        "F6 the vault is not kept for the refresh token's life",
        "service.py",
        "            self.vault.put(subject_ref, data, hold, offer_id)\n",
        "            pass\n",
    ),
    (
        "F7 a reused code leaves its refresh token",
        "service.py",
        '            self.store.delete("refresh", refresh_key)\n',
        "",
    ),
    (
        "F8 a refresh widens what was authorized",
        "authorize.py",
        'bool(wanted) and set(wanted) <= set(row["configuration_ids"]),',
        "bool(wanted),",
    ),
    (
        "F9 a refresh goes by the status period of the attestation at PAR",
        "authorize.py",
        'keeps this instance\'s status.\n                "client_status_exp": identity.status_exp,\n',
        'keeps this instance\'s status.\n                "client_status_exp": row["client_status_exp"],\n',
    ),
    (
        "F10 a refresh-able subject does not count as live",
        "service.py",
        '        if self.store.get("subject-refresh", subject_ref) is not None:\n',
        "        if False:\n",
    ),
    (
        "F11 the spent-code record forgets a code before its refresh token ends",
        "authorize.py",
        "self._settings.code_ttl, self._settings.refresh_token_ttl + self._settings.access_token_ttl)",
        "self._settings.code_ttl, self._settings.access_token_ttl)",
    ),
    (
        "F12 a refresh token may not live a full year",
        "settings.py",
        '"refresh_token_ttl": 365 * 86_400,',
        '"refresh_token_ttl": 364 * 86_400,',
    ),
    (
        "F13 the subject window leaves out the refresh token",
        "settings.py",
        "login = self.login_ttl + self.code_ttl + self.refresh_token_ttl\n",
        "login = self.login_ttl + self.code_ttl\n",
    ),
    (
        "F14 the data is held only until the refresh token ends, not its last access token",
        "service.py",
        "hold = ttl + self.settings.access_token_ttl\n",
        "hold = ttl\n",
    ),
    (
        "F15 the person link is not extended for the refresh token",
        "service.py",
        "            self._link_person_ref(subject_ref, reference, linked)\n",
        "            pass\n",
    ),
    (
        "F16 the subject is not marked as refresh-able",
        "service.py",
        '        self.store.put("subject-refresh", subject_ref, 1, hold)\n',
        "",
    ),
    (
        "F17 a refresh token lives twice as long as set",
        "authorize.py",
        "        ttl = self._settings.refresh_token_ttl\n        record = {**grant,",
        "        ttl = 2 * self._settings.refresh_token_ttl\n        record = {**grant,",
    ),
    (
        "F18 a refresh gives new credential identifiers",
        "authorize.py",
        "identifiers = {by_config.get(c) or b64u(secrets.token_bytes(16)): c",
        "identifiers = {b64u(secrets.token_bytes(16)): c",
    ),
    (
        "F19 a refresh response leaves out the scope granted",
        "authorize.py",
        'self._granted(identifiers, row.get("scopes"), configuration_ids)',
        "self._granted(identifiers, None, configuration_ids)",
    ),
    # M3 piece C: the safe fetcher and revocation from the network (fetch.py, revocation.py)
    (
        "C1 the fetcher connects to the name, not the address it checked",
        "fetch.py",
        "socket.create_connection((address, where.port), timeout=self._left(deadline))",
        "socket.create_connection((where.host, where.port), timeout=self._left(deadline))",
    ),
    ("C2 the time budget is never enforced", "fetch.py", "        timer.start()\n", "        pass\n"),
    (
        "C3 the limit per host never forgets a request",
        "fetch.py",
        "            sent = self._sent.setdefault(host, deque())\n            while sent and sent[0] <= now - 60:",
        "            sent = self._sent.setdefault(host, deque())\n            while False:",
    ),
    (
        "C4 an IPv6 address in the NAT64 prefix is judged without the IPv4 address in it",
        "fetch.py",
        "            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))\n",
        "            pass\n",
    ),
    (
        "C6 no single flight: every caller fetches",
        "revocation.py",
        "            with entry[0]:\n                yield\n",
        "            yield\n",
    ),
    (
        "C7 an OCSP answer in hand is used past its nextUpdate",
        "revocation.py",
        "        if not held.this_update - SKEW <= now <= held.next_update:\n            return False\n",
        "        if not held.this_update - SKEW <= now:\n            return False\n",
    ),
    (
        "C8 the caches grow without bound",
        "revocation.py",
        "while len(self._entries) > self._size:",
        "while False:",
    ),
    (
        "C10 a delegate's status is asked of nobody",
        "revocation.py",
        "        delegate_status(signer, issuer)\n",
        "        pass\n",
    ),
    (
        "C11 a response signed with a weak hash is accepted",
        "revocation.py",
        "    if not agreed_hash(digest):\n        return False\n",
        "    if digest is None:\n        return False\n",
    ),
    (
        "C12 the deadline cuts the plain socket a TLS socket detached",
        "fetch.py",
        "threading.Timer(self._left(deadline), _cut, (live,))",
        "threading.Timer(self._left(deadline), _cut, ([sock],))",
    ),
    (
        "C13 a DNS lookup is not bounded by the budget",
        "fetch.py",
        "answers = _resolve_within(self._resolve, where.host, where.port, budget)",
        "answers = self._resolve(where.host, where.port, type=socket.SOCK_STREAM)",
    ),
    ("C14 a delegated responder is not held to the profile", "revocation.py", "        _check_responder(signer)\n", ""),
    (
        "C15 a key's lock stays in the registry",
        "revocation.py",
        "                if entry[1] == 0:\n                    del self._locks[key]\n",
        "                pass\n",
    ),
    (
        "C16 a delegate's status is not checked again when its answer is used again",
        "revocation.py",
        "            self._delegate(now)(responder, issuer)\n        return True\n",
        "            pass\n        return True\n",
    ),
    (
        "C17 a fetched CRL is kept whoever signed it",
        "revocation.py",
        "[crl for crl in parse_crls(data) if _signed(crl, issuer)]",
        "parse_crls(data)",
    ),
    (
        "C18 an OCSP answer is kept by key and serial, not by the whole CertID",
        "revocation.py",
        "key = (*_issuer_id(issuer), cert.serial_number)",
        "key = (_key_hash(issuer), cert.serial_number)",
    ),
    ("C19 CRLs are kept by URL alone", "revocation.py", "key = (url, *_issuer_id(issuer))", "key = url"),
    (
        "C27 a CRL dated after now counts as in force when CRLs are dropped",
        "revocation.py",
        "    return crl.next_update_utc is not None and crl.last_update_utc <= now <= crl.next_update_utc\n",
        "    return crl.next_update_utc is not None and now <= crl.next_update_utc\n",
    ),
    (
        "C5 CRLs in hand stand in for a fetch whatever their dates",
        "revocation.py",
        "    return newest is not None and (seen is None or newest >= seen)\n",
        "    return True\n",
    ),
    (
        "C9 the operator's CRL file is left out when a distribution point is fetched",
        "revocation.py",
        "        crls = [*source.crls, *self._local_crls()]\n",
        "        crls = list(source.crls)\n",
    ),
    (
        "C21 a failed fetch forgets the distribution point",
        "revocation.py",
        "            except (FetchError, ValueError):\n                return source\n",
        "            except (FetchError, ValueError):\n                return _Source([], None)\n",
    ),
    (
        "C24 a CRL dated after now counts as the newest seen",
        "revocation.py",
        "if _in_force(crl, now) and _signed(crl, issuer)",
        "if _signed(crl, issuer)",
    ),
    (
        "C26 a fetch with more than sixteen CRLs is kept",
        "revocation.py",
        "            if len(fetched) > MAX_HELD:\n",
        "            if False:\n",
    ),
    (
        "C28 a fetch with more than sixteen CRLs forgets the newest of them",
        "revocation.py",
        "                self._remember(key, None, newest)\n                raise JoseError(OVERFLOW)",
        "                raise JoseError(OVERFLOW)",
    ),
    (
        "C29 the CRLs in hand do not count as seen before a fetch replaces them",
        "revocation.py",
        "_latest(_newest_issued(source.crls, issuer, now), _newest_issued(fetched, issuer, now))",
        "_latest(_newest_issued(fetched, issuer, now))",
    ),
    (
        "C31 a CRL dated after now counts as seen",
        "revocation.py",
        "if crl.last_update_utc <= now and _signed(crl, issuer)",
        "if _signed(crl, issuer)",
    ),
    (
        "C33 the newest CRL seen can be written lower",
        "revocation.py",
        "stored = _Source(kept, _latest(current.newest if current is not None else None, seen))",
        "stored = _Source(kept, seen)",
    ),
    (
        "C20 a check does not count the CRLs it sees as seen",
        "revocation.py",
        "self._remember(key, None, _latest(source.newest, _newest_issued(crls, issuer, now))).newest",
        "self._remember(key, None, source.newest).newest",
    ),
    (
        "C30 a check decides by its own view, not by what is stored once it is merged in",
        "revocation.py",
        "        seen = self._remember(key, None, _latest(source.newest, _newest_issued(crls, issuer, now))).newest\n",
        "        seen = _latest(source.newest, _newest_issued(crls, issuer, now))\n"
        "        self._remember(key, None, seen)\n",
    ),
    # M3 piece H: wallet providers' status lists (wallet_status.py, client_auth.py, proofs.py)
    (
        "H1 a wallet attestation's status is not checked",
        "client_auth.py",
        '                self._wallet_status.check(claims["client_status"])\n',
        "                pass\n",
    ),
    (
        "H2 a key attestation's status is not checked",
        "proofs.py",
        "                self._wallet_status.check(status)\n",
        "                pass\n",
    ),
    (
        "H3 an entry is read from the high end of its byte",
        "wallet_status.py",
        "(listed.statuses[at // 8] >> (at % 8))",
        "(listed.statuses[at // 8] >> (8 - listed.bits - at % 8))",
    ),
    (
        "H4 a list is kept past its exp",
        "wallet_status.py",
        "until = min(float(exp), now + (ttl if ttl is not None else LIFETIME), now + LIFETIME)\n"
        "        return _List(_inflated(lst)",
        "until = min(now + (ttl if ttl is not None else LIFETIME), now + LIFETIME)\n"
        "        return _List(_inflated(lst)",
    ),
    (
        "H5 a list without a ttl is kept for a day",
        "wallet_status.py",
        "now + (ttl if ttl is not None else LIFETIME), now + LIFETIME)\n        return _List(_inflated(lst)",
        "now + (ttl if ttl is not None else 86_400), now + 86_400)\n        return _List(_inflated(lst)",
    ),
    (
        "H6 the status list signer's revocation is not checked",
        "wallet_status.py",
        "revocation=self._trust.revocation(),",
        "revocation=None,",
    ),
    (
        "H7 a list is inflated without a cap",
        "wallet_status.py",
        "inflater.decompress(packed, MAX_LIST + 1)",
        "inflater.decompress(packed)",
    ),
    (
        "H8 wallet providers' status lists go by the wall clock",
        "service.py",
        "WalletStatus(self.fetcher, self.trust, self.time, self.store)",
        "WalletStatus(self.fetcher, self.trust, clock, self.store)",
    ),
    (
        "H9 a list in hand is used without judging its signer again",
        "wallet_status.py",
        "        self._trusted(listed.chain, now)\n        return listed\n",
        "        return listed\n",
    ),
    (
        "H10 an older list is not checked against the newest seen",
        "wallet_status.py",
        "            self._raise_watermark(uri, fetched.iat)\n",
        "",
    ),
    (
        "H11 a list in hand is used though a newer one was seen at its URI",
        "wallet_status.py",
        "        return self._clock() < held.until and not (isinstance(seen, int) and held.iat < seen)\n",
        "        return self._clock() < held.until\n",
    ),
    (
        "H12 the mark of the newest list seen is kept no longer than a list may live",
        "wallet_status.py",
        "WATERMARK_TTL = MAX_LIFETIME + 86_400\n",
        "WATERMARK_TTL = MAX_LIFETIME\n",
    ),
    # M3 piece B: the Commission's list of wallet providers (lote.py)
    (
        "B2 the highest sequence number seen is not kept",
        "lote.py",
        '                self._store.put("lote-sequence", "wallet-providers", read.sequence, None)\n',
        "                pass\n",
    ),
    (
        "B4 a revocation service's certificates become attestation anchors",
        "lote.py",
        "                revocation.extend(certificates)\n",
        "                issuance.extend(certificates)\n",
    ),
    (
        "B7 the depth of the list is undercounted",
        "lote.py",
        "stack.extend((child, level + 1)",
        "stack.extend((child, level)",
    ),
    (
        "B8 a list may run seven months",
        "lote.py",
        "    month = at.month + 6\n",
        "    month = at.month + 7\n",
    ),
    (
        "B10 a list may run past the end of a shorter month",
        "lote.py",
        "day=min(at.day, calendar.monthrange(year, month)[1])",
        "day=min(at.day, 28) + 3",
    ),
    (
        "B9 the list file is not read again when it changes",
        "lote.py",
        "            if stamp != self._stamp or retry:\n",
        "            if retry:\n",
    ),
    (
        "B11 the list file is read whole before its size is judged",
        "lote.py",
        "            data = file.read(MAX_LOTE + 1)",
        "            data = file.read()",
    ),
    (
        "B12 a list another worker superseded still gives its anchors",
        "lote.py",
        "        if isinstance(highest, int) and listed.sequence < highest:\n            # Another worker",
        "        if False:\n            # Another worker",
    ),
    (
        "B13 a refresh that fails keeps the list in hand",
        "lote.py",
        "                    self._list = None\n",
        "                    pass\n",
    ),
    (
        "B14 a read that failed is never tried again",
        "lote.py",
        "                    self._retry_at = self._clock() + RETRY\n",
        "                    pass\n",
    ),
    ("B15 a read that failed is tried again at once", "lote.py", "RETRY = 60  #", "RETRY = 0  #"),
    # M3 piece G: signed metadata, issuer_info and the reuse policy of TS 119 472-3 (signed_metadata.py, metadata.py)
    (
        "G1 the signed metadata names another subject",
        "signed_metadata.py",
        '"sub": document["credential_issuer"]',
        '"sub": "x"',
    ),
    (
        "G2 a tie between JSON and JWT goes to the JWT",
        "signed_metadata.py",
        "return jwt > 0 and jwt > json_",
        "return jwt > 0 and jwt >= json_",
    ),
    (
        "G3 the signed metadata is never signed again",
        "service.py",
        "if held is not None and held[0] == now // 60 and now < held[2]:",
        "if held is not None and now < held[2]:",
    ),
    ("G4 issuer_info is not published", "metadata.py", '        document["issuer_info"] = info\n', "        pass\n"),
    (
        "G5 the access signer is not checked at the start",
        "service.py",
        "            check_access_signer(self.signers.access, self.signers.credentials, self.signers.status)\n",
        "            pass\n",
    ),
    (
        "G6 the two spellings of method B are two methods",
        "metadata.py",
        '"limited_time" if d == "limited-time" else d for d in details',
        "d for d in details",
    ),
    (
        "G7 the signed metadata lives a day whatever is set",
        "signed_metadata.py",
        '"exp": now + ttl',
        '"exp": now + 86_400',
    ),
    (
        "G8 a signed document is served after its exp",
        "service.py",
        "if held is not None and held[0] == now // 60 and now < held[2]:",
        "if held is not None and held[0] == now // 60:",
    ),
    (
        "G9 a wildcard undoes an explicit weight",
        "signed_metadata.py",
        'for name in (kind, "application/*", "*/*"):',
        'for name in ("*/*", "application/*", kind):',
    ),
    (
        "I1 attestation signers are trusted under the list's status list anchors",
        "trust.py",
        "return current.issuance if current is not None else []",
        "return current.revocation if current is not None else []",
    ),
    (
        "I2 status list signers are trusted under the list's attestation anchors",
        "trust.py",
        "return current.revocation if current is not None else []",
        "return current.issuance if current is not None else []",
    ),
    (
        "I3 the operator's CRL file is left out once the list is used",
        "trust.py",
        "FetchedRevocation(fetcher, crls)",
        "FetchedRevocation(fetcher, None)",
    ),
    (
        "I4 the pinned list signer file may hold several certificates",
        "trust.py",
        "        if len(signer) != 1:\n",
        "        if not signer:\n",
    ),
    (
        "I5 with the list, wallet providers' status lists are not checked",
        "trust.py",
        "return cls(issuance, status, FetchedRevocation(fetcher, crls), start)",
        "return cls(issuance, None, FetchedRevocation(fetcher, crls), start)",
    ),
    (
        "I6 the list goes by the wall clock",
        "service.py",
        "Trust.from_settings(settings, self.store, self.time, self.fetcher)",
        "Trust.from_settings(settings, self.store, clock, self.fetcher)",
    ),
    (
        "I7 without the list, the operator's status list anchors are ignored",
        "trust.py",
        "(lambda: status_anchors) if status_anchors is not None else None,",
        "None,",
    ),
    (
        "I8 without the list, the operator's CRL file is ignored",
        "trust.py",
        "_FileRevocation(crls) if crls is not None else None,\n        )\n\n    @classmethod",
        "None,\n        )\n\n    @classmethod",
    ),
    (
        "I9 a wallet attestation signer's revocation is not checked",
        "client_auth.py",
        "revocation=self._trust.revocation(),",
        "revocation=None,",
    ),
    (
        "I10 a list renamed over the old one in the same clock tick is not read",
        "lote.py",
        "return status.st_ino, status.st_mtime_ns, status.st_size",
        "return 0, status.st_mtime_ns, status.st_size",
    ),
    (
        "P11 a CRL file renamed over the old one in the same clock tick is not read",
        "proofs.py",
        "return status.st_ino, status.st_mtime_ns, status.st_size",
        "return 0, status.st_mtime_ns, status.st_size",
    ),
    (
        "P12 the CRL file's stamp is taken after its first read",
        "proofs.py",
        "        self._stamp = self._current_stamp()\n"
        "        try:\n            self._crls = parse_crls(path.read_bytes())\n"
        "        except (OSError, ValueError) as exc:\n"
        '            raise ConfigError(f"cannot use the wallet provider CRLs in {path}: {exc}") from exc\n',
        "        try:\n            self._crls = parse_crls(path.read_bytes())\n"
        "        except (OSError, ValueError) as exc:\n"
        '            raise ConfigError(f"cannot use the wallet provider CRLs in {path}: {exc}") from exc\n'
        "        self._stamp = self._current_stamp()\n",
    ),
    (
        "L1 credentials carry no vct#integrity",
        "credentials.py",
        '        **({"vct#integrity": integrity} if integrity is not None else {}),\n',
        "",
    ),
    (
        "L2 every qualified or public-body attestation is called qualified",
        "credentials.py",
        '{"category": CATEGORIES[settings.profile], "jti": attestation_id()}',
        '{"category": "urn:etsi:esi:eaa:eu:qualified", "jti": attestation_id()}',
    ),
    (
        "L3 the Type Metadata digest is URL-safe base64, not the SRI encoding",
        "metadata.py",
        'base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")',
        'base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii")',
    ),
    (
        "L4 production starts without Type Metadata",
        "metadata.py",
        "    if settings.production:\n        untyped",
        "    if False:\n        untyped",
    ),
    (
        "L5 the issuance passes no vct#integrity",
        "service.py",
        'self.configs.integrity.get(config["vct"]),',
        "None,",
    ),
    (
        "L6 qualified and public-body providers need not name their signer by URL",
        "settings.py",
        "SIGNER_URL_PROFILES = frozenset({Profile.PID_PROVIDER, Profile.QEAA_PROVIDER, Profile.PUB_EAA_PROVIDER})",
        "SIGNER_URL_PROFILES = frozenset({Profile.PID_PROVIDER})",
    ),
    (
        "L7 a claim named category may clash with the attestation's category",
        "qualified.py",
        '    "category": "a claim named category would clash',
        '    "x-category": "a claim named category would clash',
    ),
    (
        "L8 Type Metadata is hashed as parsed, not as the bytes the wallet gets",
        "metadata.py",
        "hashlib.sha256(data).digest()",
        "hashlib.sha256(json.dumps(document).encode()).digest()",
    ),
    (
        "R1 a repeated request gets the first one's credentials for other keys",
        "service.py",
        'sorted(thumbprint(k) for k in proven.keys) == kept["keys"],',
        "True,",
    ),
    (
        "R2 the kept reply outlives a closed subject",
        "service.py",
        "        self.vault.drop_replies(subject_ref)\n",
        "",
    ),
    (
        "R3 an erasure does not count a kept reply as data held",
        "service.py",
        "held = self.vault.data_held(subject_ref) or self.vault.replies_held(subject_ref)",
        "held = self.vault.data_held(subject_ref)",
    ),
    (
        "R4 the kept reply outlives its token",
        "service.py",
        "reply, max(grant.expires - self.time(), 1))",
        "reply, max(grant.expires - self.time(), 1) * 10)",
    ),
    (
        "R5 a kept reply opens under another slot",
        "audit.py",
        "        aad = self._aad(subject_ref, slot)\n        sealed = self._kek.encrypt(",
        '        aad = self._aad(subject_ref, "")\n        sealed = self._kek.encrypt(',
    ),
    (
        "R6 a kept reply is opened under any slot",
        "audit.py",
        "raw[12:], self._aad(subject_ref, slot)))",
        'raw[12:], self._aad(subject_ref, "")))',
    ),
    (
        "R7 drop_replies drops nothing",
        "audit.py",
        '        for key, _ in self._store.items("vault-reply", f"{subject_ref}:", at=0):',
        '        for key, _ in self._store.items("vault-reply", f"{subject_ref}:", at=0)[:0]:',
    ),
    (
        "U1 a request_uri is opened without bound",
        "authorize.py",
        '"par-opens", key, self._settings.par_ttl) <= MAX_OPENS,',
        '"par-opens", key, self._settings.par_ttl) <= MAX_OPENS * 100,',
    ),
    (
        "U2 a completed login does not spend its request_uri",
        "authorize.py",
        '            self._store.delete("par", par)\n',
        "            pass\n",
    ),
    (
        "U3 two logins from one request_uri both complete",
        "authorize.py",
        'if not self._store.add("par-done", par, 1,',
        'if False and not self._store.add("par-done", par, 1,',
    ),
    (
        "U4 the request_uri is not checked again in the login's transaction",
        "authorize.py",
        'self._store.get("par", key) is not None,',
        "True,",
    ),
    (
        "K1 a token request without code_verifier is not refused as invalid_grant",
        "authorize.py",
        '            verifier is not None,\n            "OAUTH.PKCE_VERIFIER",\n            "invalid_grant",',
        '            True,\n            "OAUTH.PKCE_VERIFIER",\n            "invalid_grant",',
    ),
    (
        "K2 a DPoP jti of under 8 characters is taken",
        "oauth.py",
        'not 8 <= len(claims["jti"]) <= 256',
        'not 1 <= len(claims["jti"]) <= 256',
    ),
    (
        "K3 an attested pre-authorized request is taken as anonymous",
        "oauth.py",
        "identity = client(one) if client is not None else None",
        "identity = None",
    ),
    (
        "K4 an attested pre-authorized token is not capped by the attestation's status period",
        "oauth.py",
        '"client_status_exp": identity.status_exp,\n                        "client_status": [identity.status]',
        '"client_status_exp": None,\n                        "client_status": [identity.status]',
    ),
    (
        "K5 a pre-authorized request with only one attestation header is taken as anonymous",
        "service.py",
        "            if not attestations and not pops:",
        "            if not attestations or not pops:",
    ),
    (
        "R8 an erasure misses a reply that has expired but is not swept yet",
        "audit.py",
        '        for key, _ in self._store.items("vault-reply", f"{subject_ref}:", at=0):  # expired rows too',
        '        for key, _ in self._store.items("vault-reply", f"{subject_ref}:"):',
    ),
    (
        "R9 an erasure does not count an expired reply as data held",
        "audit.py",
        'return bool(self._store.items("vault-reply", f"{subject_ref}:", at=0))',
        'return bool(self._store.items("vault-reply", f"{subject_ref}:"))',
    ),
    # M4 piece A: CBOR and COSE
    ("MA1 map keys keep the caller's order", "cose.py", "sorted(items, key=lambda entry: entry[0])", "items"),
    (
        "MA2 map keys sorted backwards",
        "cose.py",
        "key=lambda entry: entry[0])",
        "key=lambda entry: entry[0], reverse=True)",
    ),
    (
        "MA3 tdate keeps fractions",
        "cose.py",
        """fromtimestamp(int(at), dt.UTC)
    return cbor2.CBORTag(TDATE, moment.strftime("%Y-%m-%dT%H:%M:%SZ"))""",
        """fromtimestamp(at, dt.UTC)
    return cbor2.CBORTag(TDATE, moment.isoformat().replace("+00:00", "Z"))""",
    ),
    (
        "MA4 the Sig_structure context is Signature",
        "cose.py",
        'encode(["Signature1", header',
        'encode(["Signature", header',
    ),
    (
        "MA5 the Sig_structure leaves out the protected header",
        "cose.py",
        '"Signature1", header, b"", payload',
        '"Signature1", b"", b"", payload',
    ),
    ("MA6 ES384 gets the ES256 value", "cose.py", '"ES384": -35', '"ES384": -7'),
    (
        "MA7 x5t hashes with SHA-1",
        "cose.py",
        "[SHA256, hashlib.sha256(certificate).digest()]",
        "[SHA256, hashlib.sha1(certificate).digest()]",
    ),
    (
        "MA8 COSE_Key swaps x and y",
        "cose.py",
        '{KTY: KTY_EC2, CRV: COSE_CURVES[jwk["crv"]], X: x, Y: y}',
        '{KTY: KTY_EC2, CRV: COSE_CURVES[jwk["crv"]], X: y, Y: x}',
    ),
    (
        "MA9 P-384 is COSE curve 3",
        "cose.py",
        'COSE_CURVES = {"P-256": 1, "P-384": 2, "P-521": 3}',
        'COSE_CURVES = {"P-256": 1, "P-384": 3, "P-521": 2}',
    ),
    ("MA10 decode allows duplicate map keys", "cose.py", "allow_duplicate_keys=False", "allow_duplicate_keys=True"),
    ("MA11 decode allows indefinite lengths", "cose.py", "allow_indefinite=False", "allow_indefinite=True"),
    ("MA12 decode turns dates into Python dates", "cose.py", "semantic_decoders=RAW_TAGS", "semantic_decoders=None"),
    (
        "MA13 a full-date is any text",
        "cose.py",
        "if not isinstance(text, str) or not FULL_DATE_TEXT.fullmatch(text):",
        "if not isinstance(text, str):",
    ),
    (
        "MA14 embed uses cbor2's own order",
        "cose.py",
        "return cbor2.CBORTag(ENCODED_CBOR, encode(value))",
        "return cbor2.CBORTag(ENCODED_CBOR, cbor2.dumps(value))",
    ),
    (
        "MA15 one certificate goes as an array",
        "cose.py",
        "return certificates[0] if len(certificates) == 1 else list(certificates)",
        "return list(certificates)",
    ),
    (
        "MA16 any alg value is looked up",
        "cose.py",
        "name = ALGORITHM_NAMES.get(alg) if _integer(alg) else None",
        "name = ALGORITHM_NAMES.get(alg) if alg is not None else None",
    ),
    (
        "MA17 a boolean or float curve reads as its integer",
        "cose.py",
        "    return isinstance(value, int) and not isinstance(value, bool)",
        "    return isinstance(value, int | float)",
    ),
    ("MA18 the self-described CBOR mark is dropped", "cose.py", "1004, 43000, 55799)", "1004, 43000)"),
    (
        "MA19 a tagged map key keeps mutable contents",
        "cose.py",
        "        return cbor2.CBORTag(key.tag, _hashable(key.value))",
        "        return key",
    ),
    (
        "MA20 any header or key label is taken",
        "cose.py",
        "    return all(_integer(label) or isinstance(label, str) for label in entries)",
        "    return True",
    ),
    (
        "MA21 a JWK curve of any type is looked up",
        "cose.py",
        """not isinstance(jwk.get("crv"), str) or "d" in jwk""",
        """jwk.get("crv") is None or "d" in jwk""",
    ),
    # M4 piece B: mdoc issuance and the CWT status list
    (
        "MB1 an item's digest leaves out its tag 24",
        "mdoc.py",
        "hashlib.sha256(cose.encode(item)).digest()",
        "hashlib.sha256(item.value).digest()",
    ),
    (
        "MB2 digest ids count up from 0",
        "mdoc.py",
        "ids = secrets.SystemRandom().sample(range(DIGEST_IDS), len(elements))",
        "ids = list(range(len(elements)))",
    ),
    (
        "MB3 salts are 8 bytes",
        "mdoc.py",
        "SALT_BYTES = 32",
        "SALT_BYTES = 8",
    ),
    (
        "MB4 every item has the same salt",
        "mdoc.py",
        '"random": secrets.token_bytes(SALT_BYTES)',
        '"random": bytes(SALT_BYTES)',
    ),
    (
        "MB5 validFrom is the end of validity",
        "mdoc.py",
        '"validFrom": cose.tdate(nbf)',
        '"validFrom": cose.tdate(exp)',
    ),
    (
        "MB6 the MSO carries no status reference",
        "mdoc.py",
        '"status": {"status_list": {**status.claim(settings.issuer_url)["status_list"],',
        '"status": {"status_list": {**{},',
    ),
    (
        "MB7 x5t hashes nothing",
        "mdoc.py",
        "cose.x5t(signer.certificate_der())",
        'cose.x5t(b"")',
    ),
    (
        "MB8 issuerAuth signs the MSO without tag 24",
        "mdoc.py",
        "cose.encode(cose.embed(mso))",
        "cose.encode(mso)",
    ),
    (
        "MB9 a portrait is issued as its data URL",
        "mdoc.py",
        '    if kind == "jpeg":\n',
        "    if False:\n",
    ),
    (
        "MB10 a full-date is issued as plain text",
        "mdoc.py",
        "        return cose.full_date(value)",
        "        return value",
    ),
    (
        "MB11 the CWT status list is not COSE_Sign1_Tagged",
        "status.py",
        "return cose.encode(cbor2.CBORTag(cose.SIGN1, cose.sign1(self._signer, cose.encode(claims), protected, {})))",
        "return cose.encode(cose.sign1(self._signer, cose.encode(claims), protected, {}))",
    ),
    (
        "MB12 the CWT status list has no type",
        "status.py",
        'protected = {cose.TYP: "application/statuslist+cwt", cose.X5CHAIN: cose.x5chain(chain)}',
        "protected = {cose.X5CHAIN: cose.x5chain(chain)}",
    ),
    (
        "MB13 the CWT status list's x5chain is unprotected",
        "status.py",
        "cose.encode(claims), protected, {})",
        "cose.encode(claims), {cose.TYP: protected[cose.TYP]}, {cose.X5CHAIN: protected[cose.X5CHAIN]})",
    ),
    (
        "MB14 the CWT status list's iat is the moment of signing",
        "status.py",
        "self._cwt(uri, start, exp,",
        "self._cwt(uri, int(self._clock()), exp,",
    ),
    (
        "MB15 the CWT status list has 2 bits",
        "status.py",
        'CWT_STATUS_LIST: {"bits": 1,',
        'CWT_STATUS_LIST: {"bits": 2,',
    ),
    (
        "MB16 a tie in Accept gives the CWT",
        "app.py",
        'return "cwt" if weights["cwt"] > weights["jwt"] else "jwt"',
        'return "cwt" if weights["cwt"] >= weights["jwt"] else "jwt"',
    ),
    (
        "MB17 a q above 1 counts",
        "app.py",
        "weight if 0.0 <= weight <= 1.0 else 0.0",
        "weight",
    ),
    (
        "MB18 the status response does not vary by Accept",
        "app.py",
        ', "Vary": "Accept"}',
        "}",
    ),
    (
        "MB19 mdoc is published by default without a document signer",
        "metadata.py",
        'and (configs[cid].get("format") != MDOC or mdoc_alg is not None)',
        "",
    ),
    (
        "MB20 a published mdoc is bound to a JWK",
        "metadata.py",
        'published["cryptographic_binding_methods_supported"] = ["cose_key"]',
        'published["cryptographic_binding_methods_supported"] = ["jwk"]',
    ),
    (
        "MB21 the document signer's COSE algorithm is not checked",
        "metadata.py",
        "if algs is not None and ALGORITHM_VALUES[mdoc_alg] not in algs:",
        "if False:",
    ),
    (
        "MB22 an mdoc's issuance date is not filled in",
        "service.py",
        "if name in MDOC_ISSUANCE_DATES and name not in spaces.get(ns, {}) and (ns, name) not in FILLED:",
        "if False:",
    ),
    (
        "MB23 fractions reach the mdoc encoder",
        "credentials.py",
        "    if not _no_floats(data):\n",
        "    if False:\n",
    ),
    (
        "MB24 a document signer without the mdoc purpose is taken",
        "service.py",
        "    if MDOC_DS not in purposes:\n",
        "    if False:\n",
    ),
    (
        "MB25 an mdoc's expiry_date does not cap its validity",
        "service.py",
        'ends = [parse_date(members.get("expiry_date")) for members in subject.values() if isinstance(members, dict)]',
        "ends = []",
    ),
    (
        "MB26 a portrait's base64 is not decoded at the offer",
        "credentials.py",
        '        base64.b64decode(value.split(",", 1)[1], validate=True)\n',
        "        pass\n",
    ),
    (
        "MB28 an mdoc date element without a value_type takes any value",
        "credentials.py",
        'if name in MDOC_DATES and kind not in ("full-date", "full_date") and parse_date(value) is None:',
        "if False:",
    ),
    # M4 piece C: the PID as mdoc
    (
        "MC1 the PID's dates are issued as text",
        "mdoc.py",
        "            elements[name] = cose.full_date(value)\n",
        "            elements[name] = value\n",
    ),
    (
        "MC2 the PID's portrait is issued as its data URL",
        "mdoc.py",
        '            elements[name] = element_value("jpeg", value)\n',
        "            elements[name] = value\n",
    ),
    (
        "MC3 an element the configuration does not list is issued",
        "mdoc.py",
        "        if name not in listed:\n            continue\n",
        "",
    ),
    (
        "MC4 the PID goes in another namespace",
        "mdoc.py",
        "    return {PID_NAMESPACE: elements}",
        '    return {"org.iso.23220.1": elements}',
    ),
    (
        "MC5 the 150-character limit is 151",
        "credentials.py",
        "TSTR_MAX = 150",
        "TSTR_MAX = 151",
    ),
    (
        "MC6 the portrait counts against the text limit",
        "credentials.py",
        'if element != "portrait" and any(len(s) > TSTR_MAX for s in _strings(value)):',
        "if any(len(s) > TSTR_MAX for s in _strings(value)):",
    ),
    (
        "MC7 nested text is not counted",
        "credentials.py",
        "        return [s for v in value.values() for s in _strings(v)]\n",
        "        return []\n",
    ),
    (
        "MC8 a claim without an element in the configuration is dropped silently",
        "credentials.py",
        'f"{claims[e]}: the mdoc PID configuration has no data element {e}" for e in sorted(set(names) - set(listed))',
        'f"{claims[e]}: the mdoc PID configuration has no data element {e}" for e in []',
    ),
    (
        "MC9 the mdoc configuration's mandatory elements are not required",
        "credentials.py",
        'if claim.get("mandatory") and e not in names and e != "issuance_date"',
        "if False",
    ),
    (
        "MC10 the SD-JWT address is not mapped",
        "credentials.py",
        "        elements |= {PID_MDOC_ADDRESS[m]: v for m, v in address.items() if m in PID_MDOC_ADDRESS}\n",
        "        pass\n",
    ),
    (
        "MC11 a PID claim outside the Annex is published",
        "metadata.py",
        '        holder["claims"] = [c for c in holder["claims"] if not _names(c, outside)]\n',
        "        pass\n",
    ),
    (
        "MC12 a domestic namespace is taken for the PID",
        "metadata.py",
        "        if is_pid(config) and path[0] != PID_NAMESPACE:\n",
        "        if False:\n",
    ),
    (
        "MC13 the mdoc PID may have another document type",
        "metadata.py",
        "    if is_pid(config) and doctype != PID_DOCTYPE:\n",
        "    if False:\n",
    ),
    (
        "MC14 production takes a PID provider with one format",
        "metadata.py",
        "        if not {SDJWT, MDOC} <= formats:\n",
        "        if not formats:\n",
    ),
    (
        "MC15 a PID may be offered in one format",
        "service.py",
        "not offered or offered == published,",
        "True,",
    ),
    (
        "MC16 the mdoc PID's issuance date is not filled in",
        "service.py",
        '            if "issuance_date" in listed and "date_of_issuance" not in out:\n',
        "            if False:\n",
    ),
    (
        "MC17 the mdoc PID's validity ignores date_of_expiry",
        "service.py",
        'if config.get("format") == metadata.MDOC and not metadata.is_pid(config):',
        'if config.get("format") == metadata.MDOC:',
    ),
    (
        "MC18 the mdoc PID's text elements take any type",
        "credentials.py",
        "        if element in PID_MDOC_TEXT and (not isinstance(value, str) or not value.strip()):\n",
        "        if False:\n",
    ),
    (
        "MC19 the mdoc PID's administrative dates are not read",
        "credentials.py",
        'JPEG bytes.\n    for name in ("date_of_issuance", "date_of_expiry"):\n'
        "        if name in data and parse_date(data[name]) is None:",
        'JPEG bytes.\n    for name in ("date_of_issuance", "date_of_expiry"):\n        if False:',
    ),
    (
        "MC20 the mdoc PID's portrait base64 is not decoded at the offer",
        "credentials.py",
        'if "picture" in data and data["picture"] != "" and not _jpeg_data_url(data["picture"]):',
        "if False:",
    ),
    (
        "MC21 a null picture passes as the opt-out",
        "credentials.py",
        'if "picture" in data and picture != "" and (',
        'if picture not in (None, "") and (',
    ),
    (
        "MC22 the SD-JWT VC PID's claims outside the Annex are kept",
        "metadata.py",
        "    return sorted(p for p in paths if p in SDJWT_OUTSIDE_ANNEX)",
        "    return []",
    ),
    (
        "MC23 trust_anchor is a PID claim again",
        "credentials.py",
        '        "date_of_issuance",\n    }\n)',
        '        "date_of_issuance",\n        "trust_anchor",\n    }\n)',
    ),
    (
        "MC24 address.house_number is a PID member again",
        "credentials.py",
        '{"formatted", "country", "region", "locality", "postal_code", "street_address"}',
        '{"formatted", "country", "region", "locality", "postal_code", "street_address", "house_number"}',
    ),
    (
        "MC25 a claim outside the Annex is refused without its reason",
        "credentials.py",
        '        OUTSIDE_ANNEX.get(name, f"{name}: not a PID claim name (PID Rulebook §4.1.1)")',
        '        f"{name}: not a PID claim name (PID Rulebook §4.1.1)"',
    ),
    # M4: the mdoc status list's trust anchor (piece B follow-up)
    (
        "MD1 an mdoc names no trust anchor for its status list",
        "mdoc.py",
        ', "certificate": status_anchor}}',
        "}}",
    ),
    (
        "MD2 the status anchor is any certificate with the right name",
        "service.py",
        "            top.verify_directly_issued_by(candidate)\n",
        "            pass\n",
    ),
    (
        "MD3 the status anchor is the top of the chain itself",
        "service.py",
        "        return candidate.public_bytes(serialization.Encoding.DER)\n",
        "        return top.public_bytes(serialization.Encoding.DER)\n",
    ),
    # M4 piece E: identifier lists
    (
        "ME1 an identifier list is kept past its exp",
        "wallet_status.py",
        "until = min(float(exp), now + (ttl if ttl is not None else LIFETIME), now + LIFETIME)\n"
        '        return _List(b""',
        'until = min(now + (ttl if ttl is not None else LIFETIME), now + LIFETIME)\n        return _List(b""',
    ),
    (
        "ME2 a listed identifier is taken as valid",
        "wallet_status.py",
        "        if found.id in listed.ids:\n",
        "        if False:\n",
    ),
    (
        "ME3 an identifier list of another type is read",
        "wallet_status.py",
        "        if header.get(cose.TYP) != IDENTIFIER_TYP:\n",
        "        if False:\n",
    ),
    (
        "ME4 an identifier list for another URI is read",
        "wallet_status.py",
        "if not isinstance(claims, dict) or claims.get(CWT_SUB) != uri:",
        "if not isinstance(claims, dict):",
    ),
    (
        "ME5 an identifier list's signer is not checked",
        "wallet_status.py",
        "        self._trusted(chain, now)  # after the signature: checking the path may fetch the"
        " chain's revocation\n",
        "",
    ),
    (
        "ME6 an identifier list is not checked for replay",
        "wallet_status.py",
        "            self._raise_watermark(uri, fetched.iat)\n",
        "",
    ),
    (
        "ME7 a revocation reads as an unknown status",
        "wallet_status.py",
        'raise Revoked("the attestation is revoked on its wallet provider\'s identifier list")',
        'raise StatusError("the attestation is revoked on its wallet provider\'s identifier list")',
    ),
    (
        "ME8 a wallet attestation on an identifier list is refused",
        "client_auth.py",
        "            found = references(status)\n",
        "            found = [r for r in references(status) if r.idx is not None]\n",
    ),
    # M4 piece E: revocation chaining
    (
        "ME9 chaining never revokes on a revocation",
        "service.py",
        '        if "revoked" in verdicts or ("unknown" in verdicts and stale is not None):\n',
        '        if "unknown" in verdicts and stale is not None:\n',
    ),
    (
        "ME10 chaining revokes on an outage",
        "service.py",
        '                if "revoked" not in verdicts and not overdue:\n                    return "unchecked"\n',
        "",
    ),
    (
        "ME11 a credential of a day or less is chained",
        "service.py",
        "        return chains and exp - nbf > DAY\n",
        "        return chains\n",
    ),
    (
        "ME12 every attestation provider chains",
        "service.py",
        "chains = self.settings.profile is Profile.PID_PROVIDER or self.settings.chain_attestations",
        "chains = True",
    ),
    (
        "ME13 the key attestations are not watched",
        "service.py",
        "for member in (*grant.client_status, *own):",
        "for member in (*grant.client_status,):",
    ),
    (
        "ME14 the wallet attestations are not watched",
        "service.py",
        "for member in (*grant.client_status, *own):",
        "for member in (*own,):",
    ),
    (
        "ME15 the chaining interval is ignored",
        "service.py",
        "if not force and isinstance(last, int | float) and 0 <= now - last < interval:",
        "if False:",
    ),
    (
        "ME16 two workers both run the job",
        "service.py",
        '            if not self.store.add("chain-run", "lease", lease, interval):\n                if not force:\n',
        '            if not self.store.add("chain-run", "lease", lease, interval):\n                if False:\n',
    ),
    (
        "ME17 a successful check does not restart the unchecked period",
        "service.py",
        '                self.store.put("chain", key, {**current, "ok": int(now)}, ttl)\n',
        "                pass\n",
    ),
    (
        "ME18 a revoked subject keeps its chaining rows",
        "service.py",
        '            for key, _ in self.store.items("chain", f"{subject_ref}:", at=0):\n'
        '                self.store.delete("chain", key)\n',
        "",
    ),
    (
        "ME19 the attestation at PAR is not watched",
        "authorize.py",
        '"client_status": _distinct(taken.get("client_status"), identity.status),',
        '"client_status": _distinct(identity.status),',
    ),
    (
        "ME20 a pre-authorized token's attestation is not watched",
        "oauth.py",
        '"client_status": [identity.status] if identity.status else [],',
        '"client_status": [],',
    ),
    (
        "ME21 a refreshed token's attestation is not watched",
        "authorize.py",
        '                "client_status": _distinct(identity.status),\n',
        '                "client_status": [],\n',
    ),
    (
        "ME22 an unreadable list is not alerted on",
        "service.py",
        '        if counts["chain_unchecked"]:\n',
        "        if False:\n",
    ),
    (
        "ME23 a revocation is logged as an outage",
        "service.py",
        'reason = "wallet_revoked" if "revoked" in verdicts else "wallet_unchecked"',
        'reason = "wallet_unchecked"',
    ),
    (
        "ME24 a run reads a list for every entry of it",
        "service.py",
        "            states.update(self.wallet_status.verdicts(sorted(entries, key=lambda r: (r.idx or 0, r.id"
        ' or b""))))\n',
        "            for one in entries:\n                states.update(self.wallet_status.verdicts([one]))\n",
    ),
    (
        "ME25 a list that cannot be used leaves only one entry unknown",
        "wallet_status.py",
        '            return {each: "unknown" for each in found}\n',
        '            return {found[0]: "unknown"}\n',
    ),
    (
        "ME26 the background loop leaves chaining to maintenance",
        "app.py",
        "                await run_in_threadpool(issuer.chain)\n",
        "",
    ),
    (
        "ME28 a check writes back a row a revocation deleted",
        "service.py",
        '            if isinstance(current, dict) and float(current.get("ok", 0)) < now:\n',
        '            if float((current or row).get("ok", 0)) < now:\n                current = current or row\n',
    ),
    (
        "ME29 a credential is chained to every key attestation of its batch",
        "service.py",
        "own = proven.key_status.get(thumbprint(key), []) if key is not None else []",
        "own = [m for held in proven.key_status.values() for m in held]",
    ),
    (
        "ME30 a chaining run takes a list kept from before it",
        "wallet_status.py",
        "identifiers=found[0].id is not None, fresh=True",
        "identifiers=found[0].id is not None, fresh=False",
    ),
    (
        "ME31 an entry the run did not collect is not read",
        "service.py",
        "        for each in found:\n"
        "            if each not in states:\n"
        "                states.update(self.wallet_status.verdicts([each]))\n",
        "",
    ),
    (
        "ME32 a run renews another worker's lease",
        "service.py",
        '            if self.store.get("chain-run", "lease") != lease:\n                raise LeaseLost\n',
        "",
    ),
    (
        "ME33 a run does not renew its lease after a list",
        "service.py",
        "            self._keep_lease(lease)\n        counts = ",
        "        counts = ",
    ),
    (
        "ME34 a run takes back a lease it lost when it ends",
        "service.py",
        '                if self.store.get("chain-run", "lease") == lease:\n                   '
        ' self.store.delete("chain-run", "lease")\n',
        '                self.store.delete("chain-run", "lease")\n',
    ),
    (
        "ME35 an older check writes over a newer one",
        "service.py",
        '            if isinstance(current, dict) and float(current.get("ok", 0)) < now:\n',
        "            if isinstance(current, dict):\n",
    ),
    (
        "ME36 overdue goes by the row as the run read it",
        "service.py",
        '                overdue = stale is not None and now - float(current.get("ok", now)) > stale * DAY\n',
        '                overdue = stale is not None and now - float(row.get("ok", now)) > stale * DAY\n',
    ),
    (
        "ME37 a forced run leaves the lease to the other run",
        "service.py",
        '                self.store.put("chain-run", "lease", lease, interval)  # a forced run takes it; the'
        " other one stops\n",
        "",
    ),
    (
        "ME38 a chaining interval shorter than a list's fetch is taken",
        "settings.py",
        "        if not 600 <= self.chain_interval <= 86_400:\n",
        "        if self.chain_interval > 86_400:\n",
    ),
    # M4 piece F: deferred issuance and notification
    (
        "MF1 a subject held for review is issued at once",
        "service.py",
        "        if grant.review:\n",
        "        if False:\n",
    ),
    (
        "MF2 a collected issuance stays collectable",
        "service.py",
        '                    self.store.delete("deferred", held)\n',
        "",
    ),
    (
        "MF3 a collection does not check its row in the log transaction",
        "service.py",
        "                        self._held(held) is not None,\n",
        "                        True,\n",
    ),
    (
        "MF4 a refused issuance is collected",
        "service.py",
        '            row["state"] != "refused",\n',
        "            True,\n",
    ),
    (
        "MF5 a decision is taken again",
        "service.py",
        '                isinstance(row, dict) and row["state"] == "held",\n',
        "                isinstance(row, dict),\n",
    ),
    (
        "MF6 closing a subject keeps what is held",
        "service.py",
        '        for key, _ in self.store.items("deferred", f"{subject_ref}:", at=0):  # nothing held is issued any'
        " more\n",
        "        for key, _ in []:  # nothing held is issued any more\n",
    ),
    (
        "MF9 an event is logged at every notification",
        "service.py",
        '            if self.store.add("notified", f"{ref}:{event}", 1, self._subject_window()):\n',
        '            if self.store.add("notified", f"{ref}:{event}", 1, self._subject_window()) or True:\n',
    ),
    (
        "MF10 another login's notification_id is taken",
        "service.py",
        '            isinstance(row, dict) and row["subject_ref"] == grant.subject_ref,\n',
        "            isinstance(row, dict),\n",
    ),
    (
        "MF11 a pre-authorized offer is held",
        "service.py",
        '            body.get("review", False) is False,\n',
        "            True,\n",
    ),
    (
        "MF12 a deferred issuance keeps the 202 reply",
        "service.py",
        "                    self.vault.drop_reply(grant.subject_ref, slot)\n",
        "                    pass\n",
    ),
    (
        "MF13 the held row is stored for the token's life",
        "service.py",
        '            "exp": int(now + hold),\n',
        '            "exp": int(grant.expires),\n',
    ),
    (
        "MF14 a held issuance is collected without its key attestations read again",
        "service.py",
        "        if self.wallet_status is not None:\n            # The keys' attestations were checked",
        "        if False:\n            # The keys' attestations were checked",
    ),
    (
        "MG1 an encrypted response is never made",
        "service.py",
        "        if key is None:\n            return Reply(body)\n",
        "        if True:\n            return Reply(body)\n",
    ),
    (
        "MG2 the app answers the JWE's content as JSON",
        "app.py",
        "        if reply.jwe is not None:\n",
        "        if False:\n",
    ),
    (
        "MG3 apu and apv are left out of the request's key",
        "jwe.py",
        "        cek = concat_kdf(key.exchange(ec.ECDH(), epk), enc, apu, apv)\n",
        '        cek = concat_kdf(key.exchange(ec.ECDH(), epk), enc, b"", b"")\n',
    ),
    (
        "MG4 the KDF gives the key length in bytes",
        "jwe.py",
        'struct.pack(">I", length * 8)\n',
        'struct.pack(">I", length)\n',
    ),
    (
        "MG5 the request's protected header is not authenticated",
        "jwe.py",
        '            return AESGCM(cek).decrypt(iv, ciphertext + tag, protected.encode("ascii"))\n',
        "            return AESGCM(cek).decrypt(iv, ciphertext + tag, None)\n",
    ),
    (
        "MG6 the wallet's kid is not echoed",
        "jwe.py",
        '            header["kid"] = self.kid\n',
        "            pass\n",
    ),
    (
        "MG7 the metadata leaves out the request keys",
        "service.py",
        "self.issuer_info, self.request_keys)\n",
        "self.issuer_info)\n",
    ),
    (
        "MH1 an HSM or KMS signature is used unchecked",
        "signer.py",
        "            self._public.verify(encode_dss_signature(r, s), data, ec.ECDSA(CURVES[self.alg][2]))\n",
        "            pass\n",
    ),
    (
        "MH2 no signature at the start",
        "signer.py",
        '            self.sign(b"cunho start-up signature check")  # type: ignore[attr-defined]\n',
        "            pass\n",
    ),
    (
        "MH3 KMS is sent the message, not its digest",
        "signer.py",
        "                Message=self._digest(data),\n",
        "                Message=data,\n",
    ),
    (
        "MH4 the KMS key follows the alias, not the ARN found at the start",
        "signer.py",
        '        self._key_id, self._algorithm = str(described["KeyId"]), KMS_SPECS[spec][1]\n',
        "        self._key_id, self._algorithm = key_id, KMS_SPECS[spec][1]\n",
    ),
    (
        "MH5 a failing HSM session is not given back",
        "signer.py",
        "                        self._close()\n                        self._token.log_in()\n",
        "                        self._token.log_in()\n",
    ),
    (
        "MI1 PostgreSQL writers do not take the writer lock",
        "store.py",
        '                db.execute("SELECT pg_advisory_xact_lock(%s)", (WRITE_LOCK,))\n',
        "                pass\n",
    ),
    (
        "MI2 a PostgreSQL write waits for the writer lock without end",
        "store.py",
        "                db.execute(\"SELECT set_config('lock_timeout', %s, true)\", (self._lock_timeout,))\n",
        "",
    ),
    (
        "MI3 workers starting together create the table without the schema lock",
        "store.py",
        '                self._db.execute("SELECT pg_advisory_xact_lock(%s)", (SCHEMA_LOCK,))\n',
        "                pass\n",
    ),
    (
        "MI4 the clock base is read from the single row only",
        "service.py",
        '        return self._store.peek("maintenance", "clock") if stored is None else stored\n',
        '        return self._store.peek("maintenance", "clock")\n',
    ),
    (
        "MI5 a new boot compares its reading with its own base, which it has not laid yet",
        "service.py",
        "            last = self._latest()\n",
        "            last = base\n",
    ),
    (
        "MI6 a host whose time runs behind takes the latest time seen back",
        "service.py",
        "                latest = max(expected, self._seen() or expected)\n",
        "                latest = expected\n",
    ),
    (
        "MI7 the anchor's newest forced base of any boot is the floor",
        "service.py",
        "            seen = self._anchored(self._boot())\n",
        "            seen = self._anchored(None)\n",
    ),
    (
        "MI8 a PostgreSQL rollback that fails skips the undo callbacks",
        "store.py",
        "                finally:\n                    # Whatever the rollback did",
        "                else:\n                    # Whatever the rollback did",
    ),
    (
        "MJ1 the wallet gate lets any version of a listed solution through",
        "service.py",
        'entry["wallet_name"] == name and ("wallet_versions" not in entry or version in entry["wallet_versions"])',
        'entry["wallet_name"] == name',
    ),
    (
        "MJ2 the credential endpoint does not gate the wallet",
        "service.py",
        "        self._wallet_gate(config, grant)\n        proven = self._proofs(",
        "        proven = self._proofs(",
    ),
    (
        "MJ3 the collection of a held issuance does not gate the wallet",
        "service.py",
        "        self._wallet_gate(config, grant)\n        subject = self.vault.get(",
        "        subject = self.vault.get(",
    ),
    (
        "MJ4 a refreshed token keeps the wallet of the first attestation",
        "authorize.py",
        'gets nothing of it.\n                "wallet": identity.wallet,',
        'gets nothing of it.\n                "wallet": row.get("wallet"),',
    ),
    (
        "MJ5 a code-flow token keeps no wallet",
        "authorize.py",
        '(same sub and key).\n                    "wallet": identity.wallet,',
        '(same sub and key).\n                    "wallet": None,',
    ),
    (
        "MJ6 a pre-authorized token keeps no wallet",
        "oauth.py",
        '                        "wallet": identity.wallet,',
        '                        "wallet": None,',
    ),
    (
        "MJ7 a configuration the profile refuses is published by default all the same",
        "metadata.py",
        "                published.discard(cid)",
        "                pass",
    ),
    (
        "MJ8 the issuing authority is the certificate's common name before its organization",
        "qualified.py",
        "for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):",
        "for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):",
    ),
    (
        "MJ9 the category of an mdoc goes into the ISO/IEC 23220-2 namespace",
        "mdoc.py",
        'elements.setdefault(ETSI_NAMESPACE, {})["category"] = CATEGORIES[settings.profile]',
        'own["category"] = CATEGORIES[settings.profile]',
    ),
    (
        "MJ10 the signed signing time of an mdoc is its end",
        "mdoc.py",
        "{cose.CWT_CLAIMS: {cose.IAT: nbf},",
        "{cose.CWT_CLAIMS: {cose.IAT: exp},",
    ),
    (
        "MJ11 any country names a qualified provider",
        "qualified.py",
        "    if country not in MEMBER_STATES:",
        "    if country is None:",
    ),
    (
        "MJ12 any organizationIdentifier is a registration number",
        "qualified.py",
        'ORGANIZATION_IDENTIFIER = re.compile(r"(?:VAT|NTR|PSD|LEI|[A-Z]{2}:)[A-Z]{2}-\\S.*")',
        'ORGANIZATION_IDENTIFIER = re.compile(r".+")',
    ),
    (
        "MJ13 the document signer of a qualified provider is not checked",
        "service.py",
        '                check_provider(self.signers.mdoc.certificate_der(), "mdoc document signer")',
        "                pass",
    ),  # Piece K: the probe found that the coarse time could start an mdoc before its document signer certificate.
    (
        "MK1 an mdoc starts at the coarse time though its signer certificate started later",
        "service.py",
        "            if nbf < started <= now:\n                nbf = started",
        "            if False:\n                nbf = started",
    ),
    (
        "MK2 a signer certificate not valid yet moves the start of an mdoc",
        "service.py",
        "            if nbf < started <= now:",
        "            if nbf < started:",
    ),
    (
        "MK3 the test login's box does not hold the credentials",
        "app.py",
        '                if value("review") == "true":',
        "                if False:",
    ),
    (
        "MK4 the test login holds the credentials for any value of its box",
        "app.py",
        '                if value("review") == "true":',
        '                if value("review"):',
    ),
    # Piece M: the certificate profiles of ISO/IEC 18013-5 Annex B, which the generator does not reach (they list
    # what is wrong rather than refuse).
    (
        "MM1 a key usage that is not critical fits",
        "annex_b.py",
        "    if found is None or not found.critical or bits != wanted:",
        "    if found is None or bits != wanted:",
    ),
    (
        "MM2 a key usage with other bits fits",
        "annex_b.py",
        "    if found is None or not found.critical or bits != wanted:",
        "    if found is None or not found.critical or not wanted <= bits:",
    ),
    (
        "MM3 no countryName is asked",
        "annex_b.py",
        "    if not cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME):",
        "    if False:",
    ),
    (
        "MM4 the authority key identifier may name another issuer",
        "annex_b.py",
        "            if aki.key_identifier != ski.digest:",
        "            if False:",
    ),
    (
        "MM5 no CRL distribution point is asked of a document signer",
        "annex_b.py",
        "    if not uris:",
        "    if False:",
    ),
    (
        "MM6 any issuerAltName is the issuer's contact",
        "annex_b.py",
        "        if names.get_values_for_type(x509.RFC822Name)"
        " or names.get_values_for_type(x509.UniformResourceIdentifier):",
        "        if True:",
    ),
    (
        "MM7 an end-entity certificate may mark other extensions critical",
        "annex_b.py",
        "    extra = sorted(e.oid.dotted_string for e in cert.extensions if e.critical and e.oid not in allowed)",
        "    extra: list[str] = []",
    ),
    (
        "MM8 an IACA may have any path length",
        "annex_b.py",
        " or not found.critical or constraints.path_length != 0:",
        " or not found.critical:",
    ),
    (
        "MM9 the document signer's purpose may be non-critical",
        "annex_b.py",
        "    if found is None or not found.critical or MDOC_DS not in found.value:",
        "    if found is None or MDOC_DS not in found.value:",
    ),
    (
        "MM10 a document signer may name another country than its IACA",
        "annex_b.py",
        "        if country and theirs and country[0].value != theirs[0].value:",
        "        if False:",
    ),
    (
        "MM11 the status list signer is not checked",
        "service.py",
        "        problems += annex_b.status_signer_problems(status, annex_b.issuer_of("
        "status, [*status_chain, *status_anchors]))",
        "        pass",
    ),
    (
        "MM12 an IACA not given is not said",
        "service.py",
        "        if iaca is None:\n            problems.append(",
        "        if False:\n            problems.append(",
    ),
    (
        "MM13 production starts with certificates outside the profiles",
        "service.py",
        "        if problems and self.settings.production:",
        "        if False:",
    ),
    (
        "MM14 the profiles are not checked",
        "service.py",
        "        if self.signers.mdoc is None or not mdocs:",
        "        if True:",
    ),
    # M5 piece A: the operator's reads of a subject's progress and of a pending login
    (
        "P5A1 an issued configuration reads pending",
        "service.py",
        '                step(key.split(":", 1)[1], float(at) if isinstance(at, int | float) else 0.0, 0, "issued")',
        "                pass",
    ),
    (
        "P5A2 an open review is hidden behind an earlier issuance",
        "service.py",
        '                step(key.split(":", 1)[1], float(at) if isinstance(at, int | float) else 0.0, 0, "issued")',
        '                step(key.split(":", 1)[1], math.inf, 0, "issued")',
    ),
    (
        "P5A2b the last review read wins, whatever its time",
        "service.py",
        "            if (at, rank) > newest.get(config_id, (-math.inf, 0)):",
        "            if True:",
    ),
    (
        "P5A2c an issuance has no time",
        "service.py",
        '                self.store.put("subject-issued", issued_at, self.time(), self._subject_window())\n',
        "",
    ),
    (
        "P5A2d a review is timed to the second",
        "service.py",
        '                    step(row["config"], float(row.get("at", row["created"])), 1, row["state"])',
        '                    step(row["config"], float(row["created"]), 1, row["state"])',
    ),
    (
        "P5A3 the wallet's notification is not shown",
        "service.py",
        '                of(key.split(":", 1)[1])["notification"] = event',
        "                pass",
    ),
    (
        "P5A4 a closed subject reads as its other state",
        "service.py",
        '            if self.store.get("subject-closed", subject_ref) is not None:\n                state = "closed"',
        '            if False:\n                state = "closed"',
    ),
    (
        "P5A5 issued as soon as one configuration is",
        "service.py",
        'elif listed and all(configurations[c]["state"] == "issued" for c in listed):',
        'elif listed and any(configurations[c]["state"] == "issued" for c in listed):',
    ),
    (
        "P5A5b completion judged on what is left to issue",
        "service.py",
        '            listed = self.store.get("subject-configs", subject_ref)\n',
        '            listed = self.store.get("subject-open", subject_ref)\n',
    ),
    (
        "P5A6 a redeemed offer reads offered",
        "service.py",
        '            elif self.store.get("subject-token", subject_ref) is not None:\n'
        '                state = "redeemed"',
        '            elif False:\n                state = "redeemed"',
    ),
    (
        "P5A7 an expired offer reads offered",
        "service.py",
        '            elif expires is not None:\n                state = "offered"',
        '            elif True:\n                state = "offered"',
    ),
    (
        "P5A8 the offer's end is shown in every state",
        "service.py",
        '"expires": expires if state == "offered" else None,',
        '"expires": expires,',
    ),
    (
        "P5A9 no token marks the subject",
        "service.py",
        '        self.store.put("subject-token", subject_ref, 1, self._subject_window())',
        "        pass",
    ),
    (
        "P5A10 the token mark is never set",
        "oauth.py",
        '            if self._minted is not None and isinstance(fields.get("subject_ref"), str):',
        "            if False:",
    ),
    (
        "P5A11 a pre-authorized offer has no end",
        "service.py",
        '            self.store.put("subject-offer", subject_ref, int(self.time()) + settings.offer_ttl, '
        "settings.offer_ttl)",
        "            pass",
    ),
    (
        "P5A12 a login's subject has no end",
        "service.py",
        '            self.store.put("subject-offer", subject_ref, int(self.time()) + settings.login_ttl, '
        "settings.login_ttl)",
        "            pass",
    ),
    (
        "P5A12b the code's end does not replace the login's",
        "authorize.py",
        '            self._store.put("subject-offer", done["subject_ref"], record["exp"], ttl)\n',
        "",
    ),
    (
        "P5A12c a narrowed token keeps the configurations left out",
        "authorize.py",
        "                    self._store.put(\n"
        '                        "subject-configs", taken["subject_ref"], configuration_ids, '
        "self._settings.subject_window\n"
        "                    )\n",
        "",
    ),
    (
        "P5A13 an offer burned by wrong tx_codes reads offered (past the limit)",
        "oauth.py",
        '                self._used_up(key, offer["subject_ref"])\n'
        '                refuse("VCI.TOKEN.TX_CODE_ERRORS", "invalid_grant", "too many wrong tx_code attempts")',
        '                self._store.delete("offer", key)\n'
        '                refuse("VCI.TOKEN.TX_CODE_ERRORS", "invalid_grant", "too many wrong tx_code attempts")',
    ),
    (
        "P5A14 an offer burned by wrong tx_codes reads offered (at the limit)",
        "oauth.py",
        '                    self._used_up(key, offer["subject_ref"])\n',
        '                    self._store.delete("offer", key)\n',
    ),
    (
        "P5A15 a repeated event overwrites a newer one",
        "service.py",
        "                about = f\"{row['subject_ref']}:{row['config']}\"\n"
        '                self.store.put("subject-event", about, str(event), self._subject_window())\n',
        "            about = f\"{row['subject_ref']}:{row['config']}\"\n"
        '            self.store.put("subject-event", about, str(event), self._subject_window())\n'
        "            if True:\n",
    ),
    (
        "P5A16 the consent screen is not told the wallet",
        "authorize.py",
        '                "wallet": identity.wallet,  # for the login service\'s consent screen '
        "(GET /admin/logins/{login_state})\n",
        "",
    ),
    (
        "P5A18 a token leaves what the subject is for to expire before it",
        "service.py",
        '        self.store.put("subject-token", subject_ref, 1, self._subject_window())\n'
        "        self._keep_configs(subject_ref)\n",
        '        self.store.put("subject-token", subject_ref, 1, self._subject_window())\n',
    ),
    (
        "P5A19 an issuance leaves what the subject is for to expire before it",
        "service.py",
        "                self._keep_configs(grant.subject_ref)\n",
        "",
    ),
    (
        "P5A20 a notification leaves what the subject is for to expire before it",
        "service.py",
        '                self._keep_configs(row["subject_ref"])\n',
        "",
    ),
    (
        "P5A21 a login a sibling completed is offered for consent",
        "authorize.py",
        '        if self._store.get("par-done", str(pending.get("par"))) is not None:\n            return None\n',
        "",
    ),
    (
        "P5A22 a login does not name the offer it came from",
        "authorize.py",
        '                "offer_ref": offer_ref(issuer_state) if issuer_state is not None else None,\n',
        "",
    ),
    (
        "P5A23 every code offer has the same reference",
        "authorize.py",
        "    return _hash(issuer_state)[:32]",
        '    return _hash("")[:32]',
    ),
    (
        "P5A17 the wallet's name and version swapped",
        "service.py",
        '        name, version = pending.get("wallet") or (None, None)',
        '        version, name = pending.get("wallet") or (None, None)',
    ),
    # the security review (research/cunho-security-review.md)
    (
        "V1 a key is claimed for the access token it came under",
        "service.py",
        '"subject-key", self._key_ref(grant.subject_ref, key), reach, max(reach - now, 1)\n',
        '"subject-key", self._key_ref(grant.grant_id, key), reach, max(reach - now, 1)\n',
    ),
    (
        "V2 the claim of a key ends with the tokens minted so far, whatever its login's refresh token can still give",
        "service.py",
        "reach = max(known if isinstance(known, int) else 0, grant.expires, grant.refresh_exp or 0)",
        "reach = max(known if isinstance(known, int) else 0, grant.expires)",
    ),
    (
        "V3 the row of a claimed key holds the key's thumbprint",
        "service.py",
        "return f\"{subject_ref}:{self.keyring.mac('subject-key', thumbprint(key))[:32]}\"",
        'return f"{subject_ref}:{thumbprint(key)}"',
    ),
    (
        "V4 a login may have four issuances of a configuration waiting",
        "service.py",
        "HELD_PER_CONFIGURATION = 3\n",
        "HELD_PER_CONFIGURATION = 4\n",
    ),
    (
        "V5 issuances waiting are counted whatever their configuration",
        "service.py",
        'sum(1 for held in waiting if held is not None and held["config"] == config_id)',
        "sum(1 for held in waiting if held is not None)",
    ),
    (
        "V6 a collection does not give its mark back",
        "service.py",
        '        finally:\n            self.store.delete("collecting", f"{grant.subject_ref}:{ref}")\n',
        "        finally:\n            pass\n",
    ),
    (
        "V7 collections that come at once all do the work",
        "service.py",
        '        if not self.store.add("collecting", f"{grant.subject_ref}:{ref}", 1, COLLECTING):',
        "        if False:",
    ),
    (
        "V8 a collection that died holds the issuance for ten minutes",
        "service.py",
        "COLLECTING = 60  #",
        "COLLECTING = 600  #",
    ),
    (
        "V9 an erasure looks for the vault entry as a request would",
        "audit.py",
        'return self._store.peek("vault-key", subject_ref) is not None',
        'return self._store.get("vault-key", subject_ref) is not None',
    ),
    (
        "V10 closing a subject leaves its refresh token row",
        "service.py",
        '            self.store.delete("refresh", str(login.get("refresh")))\n',
        "",
    ),
    (
        "V11 closing a subject leaves the row of its spent code",
        "service.py",
        '            self.store.delete("code-spent", str(login.get("code")))\n',
        "",
    ),
    (
        "V12 closing a subject leaves the note of where its login's rows are",
        "service.py",
        '            self.store.delete("subject-login", subject_ref)\n',
        "",
    ),
    (
        "V13 a login leaves no note of where its refresh token and spent code are",
        "authorize.py",
        '                self._store.put("subject-login", taken["subject_ref"], {"refresh": refresh_key,'
        ' "code": key}, ttl)\n',
        "",
    ),
    (
        "V14 an SD-JWT VC ends with date_of_expiry and no other claim",
        "service.py",
        "ends = [parse_date(subject.get(name)) for name in EXPIRY_CLAIMS]",
        'ends = [parse_date(subject.get("date_of_expiry"))]',
    ),
    (
        "V15 an expiry_date in the past is offered",
        "credentials.py",
        "    for name in EXPIRY_CLAIMS:\n        expires = parse_date(data.get(name))",
        "    for name in EXPIRY_CLAIMS[:1]:\n        expires = parse_date(data.get(name))",
    ),
    (
        "V16 an expiry_date that is no date is offered",
        "credentials.py",
        'for name in ("date_of_issuance", *EXPIRY_CLAIMS):',
        'for name in ("date_of_issuance", "date_of_expiry"):',
    ),
    (
        "V17 a reserved name is looked for at the top of subject data only",
        "credentials.py",
        "                return True\n            stack.extend(item.values())\n",
        "                return True\n",
    ),
    (
        "V18 a reserved name inside an array is passed",
        "credentials.py",
        "        elif isinstance(item, list):\n            stack.extend(item)\n    return False",
        "    return False",
    ),
    (
        "V19 the name ... is not reserved",
        "credentials.py",
        'RESERVED_NAMES = frozenset({"_sd", "..."})',
        'RESERVED_NAMES = frozenset({"_sd"})',
    ),
    (
        "V20 the name _sd is not reserved",
        "credentials.py",
        'RESERVED_NAMES = frozenset({"_sd", "..."})',
        'RESERVED_NAMES = frozenset({"..."})',
    ),
    (
        "V21 wrong transaction codes end an offer without a word in the audit log",
        "service.py",
        '                self.audit.append("offer.cancelled", "cunho", subject_ref=subject_ref,'
        ' cause="tx_code_attempts")\n',
        "",
    ),
    (
        "V22 wrong transaction codes end an offer without a word in the security log",
        "service.py",
        '        if ended:\n            security_log.warning("an offer was ended by wrong transaction codes")\n',
        "",
    ),
    (
        "V23 an offer ended by wrong transaction codes leaves its data in the vault",
        "service.py",
        '                self.audit.append("offer.cancelled", "cunho", subject_ref=subject_ref,'
        ' cause="tx_code_attempts")\n'
        "                self.vault.erase(subject_ref)\n",
        '                self.audit.append("offer.cancelled", "cunho", subject_ref=subject_ref,'
        ' cause="tx_code_attempts")\n',
    ),
    (
        "V24 an offer ended by wrong transaction codes still reads as offered",
        "service.py",
        '            if ended:\n                self.store.delete("subject-offer", subject_ref)\n',
        "            if ended:\n",
    ),
    (
        "V25 an offer ended by wrong transaction codes keeps its row",
        "service.py",
        '            ended = self.store.take("offer", offer_key) is not None\n',
        '            ended = self.store.get("offer", offer_key) is not None\n',
    ),
    (
        "V26 the count of wrong transaction codes lives one offer_ttl as it is set now",
        "oauth.py",
        'attempts = self._store.incr("tx-attempts", key, max(offer["exp"] - self._clock(), 1))',
        'attempts = self._store.incr("tx-attempts", key, self._settings.offer_ttl)',
    ),
    (
        "V27 a completed request_uri is marked for the lifetimes as they are set now",
        "authorize.py",
        'if not self._store.add("par-done", par, 1, MAX_PAR_TTL + MAX_LOGIN_TTL):',
        'if not self._store.add("par-done", par, 1, self._settings.par_ttl + self._settings.login_ttl):',
    ),
    (
        "V28 a scope that names no configuration any more is looked up as if it did",
        "authorize.py",
        "self.scopes.get(s) in configuration_ids",
        "self.scopes[s] in configuration_ids",
    ),
    (
        "V29 a token response grants an empty scope",
        "authorize.py",
        '            if granted:\n                extra["scope"] = " ".join(granted)',
        '            extra["scope"] = " ".join(granted)',
    ),
    (
        "V30 a key attestation with no status period is covered by another's",
        "proofs.py",
        "        else:\n            self.unbounded = True\n",
        "",
    ),
    (
        "V31 a key attestation with no status member at all is not counted",
        "proofs.py",
        '        proven.cap(status.get("exp") if isinstance(status, dict) else None)\n'
        "        if isinstance(status, dict):\n",
        '        if isinstance(status, dict):\n            proven.cap(status.get("exp"))\n',
    ),
    (
        "V32 a base64url value may end in a line feed",
        "jose.py",
        'B64U = re.compile(r"[A-Za-z0-9_-]*")',
        'B64U = re.compile(r"[A-Za-z0-9_-]*\\n?")',
    ),
    (
        "V33 a picture may end in a line feed",
        "credentials.py",
        'JPEG_DATA_URL = re.compile(r"data:image/jpeg;base64,[A-Za-z0-9+/]+={0,2}")',
        'JPEG_DATA_URL = re.compile(r"data:image/jpeg;base64,[A-Za-z0-9+/]+={0,2}\\n?")',
    ),
    (
        "V34 nesting is not counted",
        "jose.py",
        "stack.extend((each, depth + 1) for each in inside)",
        "stack.extend((each, depth) for each in inside)",
    ),
    (
        "V35 the framework redirects a path with a slash too many",
        "app.py",
        "lifespan=lifespan, redirect_slashes=False)",
        "lifespan=lifespan, redirect_slashes=True)",
    ),
    (
        "V36 the query is read as UTF-8",
        "app.py",
        'raw.decode("latin-1")',
        "raw.decode()",
    ),
    (
        "V37 a path may be signed with any hash that has a name",
        "jose.py",
        "return digest is not None and digest.name in PATH_HASHES",
        "return digest is not None",
    ),
    (
        "V38 SHA3-224 is an agreed hash",
        "jose.py",
        'PATH_HASHES = frozenset({"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"})',
        'PATH_HASHES = frozenset({"sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"})',
    ),
    (
        "V39 a CRL signed with a hash outside the agreed ones is read",
        "jose.py",
        "        if not agreed_hash(crl.signature_hash_algorithm):\n"
        "            continue  # a list signed with a hash a certificate may not use says nothing either\n",
        "",
    ),
    (
        "V40 a fetched CRL signed with a hash outside the agreed ones is read",
        "revocation.py",
        "    if not agreed_hash(crl.signature_hash_algorithm):\n        return False\n",
        "",
    ),
    (
        "V41 a certificate the library fails on in its own way is not refused as a certificate",
        "jose.py",
        "    except Exception as exc:  # noqa: BLE001 - ValueError, InvalidVersion...: not a certificate",
        "    except ValueError as exc:  # noqa: BLE001 - ValueError, InvalidVersion...: not a certificate",
    ),
    (
        "V42 an IPv4-compatible or IPv4-translated address is judged without the IPv4 address in it",
        "fetch.py",
        "        if ip in NAT64 or any(ip in network for network in EMBEDDING):",
        "        if ip in NAT64:",
    ),
    (
        "V43 a site-local address is public",
        "fetch.py",
        "        if ip in SITE_LOCAL:\n            return False\n",
        "",
    ),
    (
        "V44 a wallet attestation's path is checked before its signature",
        "client_auth.py",
        "        signer = chain[0].public_key()\n"
        '        if not verify(attestation.header["alg"], signer, attestation.signing_input,'
        " attestation.signature):\n"
        '            fail("WIA.SIGNATURE_X5C", "the wallet attestation signature does not verify under'
        ' its x5c certificate")\n'
        "        try:\n"
        "            validate_path(\n"
        "                chain,\n"
        "                self._trust.issuance(),\n"
        "                dt.datetime.fromtimestamp(now, dt.UTC),\n"
        "                frozenset(self._settings.wia_signer_policy_oids),\n"
        "                revocation=self._trust.revocation(),\n"
        "            )\n"
        "        except JoseError:\n"
        '            fail("WIA.CHAIN_TO_WP_LIST", "the wallet attestation is not from a trusted wallet'
        ' provider")\n'
        "        claims = attestation.payload\n",
        "        try:\n"
        "            validate_path(\n"
        "                chain,\n"
        "                self._trust.issuance(),\n"
        "                dt.datetime.fromtimestamp(now, dt.UTC),\n"
        "                frozenset(self._settings.wia_signer_policy_oids),\n"
        "                revocation=self._trust.revocation(),\n"
        "            )\n"
        "        except JoseError:\n"
        '            fail("WIA.CHAIN_TO_WP_LIST", "the wallet attestation is not from a trusted wallet'
        ' provider")\n'
        "        signer = chain[0].public_key()\n"
        '        if not verify(attestation.header["alg"], signer, attestation.signing_input,'
        " attestation.signature):\n"
        '            fail("WIA.SIGNATURE_X5C", "the wallet attestation signature does not verify under'
        ' its x5c certificate")\n'
        "        claims = attestation.payload\n",
    ),
    (
        "V45 a key attestation's path is checked before its signature",
        "proofs.py",
        '        if not verify(ka.header["alg"], chain[0].public_key(), ka.signing_input, ka.signature):\n'
        '            _proof_error("KA.VERIFY", "key attestation signature does not verify")\n'
        "        try:\n"
        "            validate_path(\n"
        "                chain,\n"
        "                self._trust.issuance(),\n"
        "                dt.datetime.fromtimestamp(now, dt.UTC),\n"
        "                frozenset(self._settings.ka_signer_policy_oids),\n"
        "                revocation=self._trust.revocation(),\n"
        "            )\n"
        "        except JoseError as exc:\n"
        '            _proof_error("KA.CHAIN_TO_WP_LIST", f"key attestation is not from a trusted wallet'
        ' provider: {exc}")\n'
        "        claims = ka.payload\n",
        "        try:\n"
        "            validate_path(\n"
        "                chain,\n"
        "                self._trust.issuance(),\n"
        "                dt.datetime.fromtimestamp(now, dt.UTC),\n"
        "                frozenset(self._settings.ka_signer_policy_oids),\n"
        "                revocation=self._trust.revocation(),\n"
        "            )\n"
        "        except JoseError as exc:\n"
        '            _proof_error("KA.CHAIN_TO_WP_LIST", f"key attestation is not from a trusted wallet'
        ' provider: {exc}")\n'
        '        if not verify(ka.header["alg"], chain[0].public_key(), ka.signing_input, ka.signature):\n'
        '            _proof_error("KA.VERIFY", "key attestation signature does not verify")\n'
        "        claims = ka.payload\n",
    ),
    (
        "V46 a status list's path is checked before its signature",
        "wallet_status.py",
        "        if not verify(alg, chain[0].public_key(), token.signing_input, token.signature):\n"
        '            raise StatusError("the wallet provider\'s status list signature does not verify")\n'
        "        self._trusted(chain, now)\n",
        "        self._trusted(chain, now)\n"
        "        if not verify(alg, chain[0].public_key(), token.signing_input, token.signature):\n"
        '            raise StatusError("the wallet provider\'s status list signature does not verify")\n',
    ),
    (
        "V47 an identifier list's path is checked before its signature",
        "wallet_status.py",
        "        key = chain[0].public_key()\n"
        "        try:\n"
        "            if not isinstance(key, ec.EllipticCurvePublicKey):",
        "        self._trusted(chain, now)\n"
        "        key = chain[0].public_key()\n"
        "        try:\n"
        "            if not isinstance(key, ec.EllipticCurvePublicKey):",
    ),
    (
        "V48 an error reading a list that is no refusal is not logged",
        "wallet_status.py",
        '                log.exception("a wallet provider\'s list could not be read")\n',
        "",
    ),
    (
        "V49 an error reading a list that is no refusal goes on as it is",
        "wallet_status.py",
        '                raise StatusError("the wallet provider\'s status list cannot be read") from exc',
        "                raise",
    ),
    (
        "V50 revocation chaining does not wait for a host's minute",
        "wallet_status.py",
        "            self._fetcher.wait_for(found[0].uri)\n",
        "",
    ),
    (
        "V51 a fetch that failed is made again by everyone who waited for it",
        "fetch.py",
        "                self._failed[url] = now + RETRY_AFTER",
        "                self._failed[url] = now",
    ),
    (
        "V52 cunho's own limit is remembered as the host's failure",
        "fetch.py",
        "        except Busy as exc:\n"
        '            log.warning("fetch from %s refused: %s", where.host, exc)\n'
        "            raise\n",
        "",
    ),
    (
        "V53 the memory of failed fetches is never pruned",
        "fetch.py",
        "                if len(self._failed) > 10_000:",
        "                if False:",
    ),
    (
        "V54 the wait for a host's minute never forgets a request",
        "fetch.py",
        "                sent = self._sent.get(host)\n                while sent and sent[0] <= now - 60:",
        "                sent = self._sent.get(host)\n                while False:",
    ),
    (
        "V55 a wait for a host's minute is always a whole minute",
        "fetch.py",
        "                free_in = sent[0] + 60 - now",
        "                free_in = 60.0",
    ),
    (
        "V56 a wait takes one turn more than it says",
        "fetch.py",
        "        for _ in range(WAITS):",
        "        for _ in range(WAITS + 1):",
    ),
    (
        "V57 a wait for a URL that is none raises instead of leaving it to the fetch",
        "fetch.py",
        "        except FetchError:\n            return  # the fetch that follows says what is wrong with the URL",
        "        except ZeroDivisionError:\n"
        "            return  # the fetch that follows says what is wrong with the URL",
    ),
    (
        "V58 wrong transaction codes end an offer the right code has already taken",
        "service.py",
        '            ended = self.store.take("offer", offer_key) is not None\n',
        '            self.store.delete("offer", offer_key)\n            ended = True\n',
    ),
    (
        "V59 the claim of a key goes by the lifetimes as they are set now",
        "service.py",
        "reach = max(known if isinstance(known, int) else 0, grant.expires, grant.refresh_exp or 0)",
        "reach = int(now) + self._subject_window()",
    ),
    (
        "V60 what earlier tokens say of a subject's reach is not asked when a key is claimed",
        "service.py",
        "reach = max(known if isinstance(known, int) else 0, grant.expires, grant.refresh_exp or 0)",
        "reach = max(grant.expires, grant.refresh_exp or 0)",
    ),
    (
        "V61 a token minted later leaves the claims of keys as they were",
        "service.py",
        "        self._keep_keys(subject_ref, expires)\n",
        "",
    ),
    (
        "V62 a token minted later moves the subject's reach and not the claims",
        "service.py",
        '        for key, until in self.store.items("subject-key", f"{subject_ref}:"):\n'
        "            if not isinstance(until, int) or until < expires:  # never shortened: most reach to"
        " the refresh token's end\n"
        '                self.store.put("subject-key", key, expires, left)\n',
        "",
    ),
    (
        "V63 a token minted later shortens the claims to its own life",
        "service.py",
        "            if not isinstance(until, int) or until < expires:  # never shortened: most reach to"
        " the refresh token's end\n",
        "            if True:\n",
    ),
    (
        "V64 a token that ends sooner moves a subject's reach back",
        "service.py",
        "        if isinstance(known, int) and known >= expires:\n            return\n",
        "",
    ),
    (
        "V65 a mint tells the issuer the time it was made, not when the token ends",
        "oauth.py",
        'self._minted(fields["subject_ref"], record["exp"])',
        'self._minted(fields["subject_ref"], int(self._clock()))',
    ),
]
