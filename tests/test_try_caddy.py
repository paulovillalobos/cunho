"""tools/try_caddy.py tries what Caddy is told on a running Caddy. Here: all of it but Docker and Caddy themselves.
The two files are read, Caddy's own reading of a Caddyfile is judged, an answer and Caddy's log are judged, requests
go to a server on this machine that stands for Caddy, and the commands given to Docker are looked at. Nothing here
starts a container: the tool does, when it is run."""

from __future__ import annotations

import contextlib
import copy
import datetime
import importlib.util
import inspect
import io
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("try_caddy_under_test", ROOT / "tools" / "try_caddy.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # its dataclasses look their module up by name
    spec.loader.exec_module(module)
    return module


TRY = tool()
CADDYFILE = TRY.caddyfile_text(ROOT / "deploy" / "Caddyfile")
COMPOSE = TRY.as_text((ROOT / "deploy" / "compose.yaml").read_bytes())


@pytest.fixture(autouse=True)
def signals_as_at_a_terminal() -> Iterator[None]:
    """The signals to end, taken as a process started at a terminal takes them, whatever these tests were started
    as: put in the background by a script, or under nohup, a process is told to ignore some of them."""
    usual = {number: signal.SIG_DFL for number in TRY.STOPS} | {signal.SIGINT: signal.default_int_handler}
    before = {number: signal.signal(number, handler) for number, handler in usual.items()}
    yield
    for number, handler in before.items():
        signal.signal(number, handler)


IMAGE = "caddy@sha256:" + "0" * 64
HOSTS = {"issuer": "issuer-0a1b2c3d.localhost", "demo": "demo-0a1b2c3d.localhost"}
BOTH = (("Strict-Transport-Security", "max-age=31536000"), ("X-Content-Type-Options", "nosniff"))

# Lines as Caddy 2.11.9 wrote them, with the addresses of a test network: one of the two kinds the Caddyfile leaves
# out of the log, one of an access log, one that the debug level brings, and what Caddy writes when it starts.
CUT_SHORT = (
    '{"level":"warn","ts":1794444583.2,"logger":"http.handlers.reverse_proxy","msg":"aborting with incomplete '
    'response","upstream":"cunho-course:8000","duration":0.0006,"request":{"remote_ip":"172.19.0.1","remote_port":'
    '"55552","client_ip":"172.19.0.1","proto":"HTTP/1.1","method":"GET","host":"issuer.localhost","uri":'
    '"/course/status/1?cut=short","headers":{"X-Forwarded-For":["172.19.0.1"]}},"error":"reading: unexpected EOF"}'
)
ACCESS = (
    '{"level":"info","ts":1794447773.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":'
    '"172.19.0.1","remote_port":"40000","client_ip":"172.19.0.1","proto":"HTTP/2.0","method":"GET","host":'
    '"issuer.localhost","uri":"/pid/status/2","headers":{}},"status":200}'
)
PATH_ONLY = '{"level":"debug","ts":1794447773.2,"logger":"http.handlers.file_server","msg":"sanitized path join"}'
AT_THE_START = (
    '{"level":"info","ts":1794444580.0,"msg":"using config from file","file":"/etc/caddy/Caddyfile"}',
    '{"level":"warn","ts":1794444580.1,"logger":"admin","msg":"admin endpoint disabled"}',
    '{"level":"warn","ts":1794444580.2,"logger":"http","msg":"HTTP/2 skipped because it requires TLS","network":'
    '"tcp","addr":":80"}',
    '{"level":"info","ts":1794444580.3,"logger":"tls.obtain","msg":"certificate obtained successfully",'
    '"identifier":"issuer.localhost","issuer":"local"}',
    '{"level":"info","ts":1794444580.4,"logger":"http.log","msg":"server running","name":"srv0","protocols":'
    '["h1","h2"]}',
    "2026/11/12 00:00:00 a line that is no JSON",
)


def answer(status: int, headers: tuple[tuple[str, str], ...] = BOTH, body: bytes = b"") -> Any:
    return TRY.Answer(status, headers, body)


def case(status: int | tuple[int, ...] = 200, **more: Any) -> Any:
    return TRY.Case("issuer", "GET", "/pid/tried", status, "a case", **more)


class Clock:
    """Time, played: it passes when something sleeps, and a little each time it is looked at."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        self.now += 0.01
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


# reading the two files -------------------------------------------------------------------------------------------


def test_what_a_file_says_is_its_lines_without_comments_and_blank_lines() -> None:
    text = "one\n\t# a comment\n   \t\ntwo # not a comment: it does not start the line\n  # another\n\tthree\n"
    assert TRY.said(text) == "one\ntwo # not a comment: it does not start the line\n\tthree\n"
    # A line ends at a line feed alone: what Python would also end a line at stays in the line, to be seen.
    assert TRY.said("one\x0ctwo\u2028three\n") == "one\x0ctwo\u2028three\n"
    assert TRY.said("one\n\x0c\n\xa0\ntwo\n") == "one\n\x0c\n\xa0\ntwo\n", "blank is spaces and tabs, nothing else"
    # Only spaces and tabs come before the # of a comment: a line that starts otherwise says something.
    assert TRY.said("\xa0# not a comment\n") == "\xa0# not a comment\n"
    assert TRY.said("x\nxx #\nx# not a comment\n") == "x\nxx #\nx# not a comment\n"


def test_a_block_is_the_lines_under_its_header_and_a_comment_does_not_end_it() -> None:
    text = "services:\n  one:\n    a: 1\n# a comment in the first column\n    b: 2\n\n  two:\n    c: 3\nvolumes:\n"
    assert TRY.block(text, "one:", "  ") == "    a: 1\n# a comment in the first column\n    b: 2\n"
    assert TRY.block(text, "two:", "  ") == "    c: 3"
    assert (
        TRY.block("x:\n  a: 1\x0c  b: 2\ny:\n", "x:", "") == "  a: 1\x0c  b: 2"
    )  # one line here: a line feed alone ends one


SHARED = 'x-logging: &logging\n  driver: json-file\n  options:\n    max-size: 10m\n    max-file: "3"\n'


def test_what_caddy_is_told_is_the_caddyfile_and_the_service_that_starts_it() -> None:
    told = TRY.told("{\n\t# why\n\tadmin off\n}\n", COMPOSE)
    own = TRY.said(TRY.block(COMPOSE, "caddy:", "  "))
    assert own.startswith("    image: caddy:") and own.endswith("    depends_on: [demo]\n")
    # With the service's own lines, what it takes by an alias: the block that `logging: *logging` stands for.
    assert told == {TRY.CADDYFILE: "{\n\tadmin off\n}\n", TRY.SERVICE: own + SHARED}
    one, other = TRY.digests("a\n", COMPOSE), TRY.digests("b\n", COMPOSE)
    assert one[TRY.SERVICE] == other[TRY.SERVICE] and one[TRY.CADDYFILE] != other[TRY.CADDYFILE]
    assert all(len(digest) == 64 for digest in one.values())


def test_a_caddyfile_is_read_as_caddy_reads_it(tmp_path: Path) -> None:
    (tmp_path / "Caddyfile").write_bytes(b"{\r\n\tadmin off\r\n}\r\n# \xc2\xa7 4.2\rnot a line end\n")
    assert TRY.caddyfile_text(tmp_path / "Caddyfile") == "{\n\tadmin off\n}\n# \xa7 4.2\rnot a line end\n"


def with_a_line(line: str) -> str:
    """The stack's Caddyfile with one more line, or more, among its global options."""
    assert CADDYFILE.count("\tadmin off\n") == 1
    return CADDYFILE.replace("\tadmin off\n", f"\tadmin off\n{line}")


def test_the_stacks_caddyfile_is_plain_and_brings_nothing_in() -> None:
    assert TRY.plain(CADDYFILE) is None and TRY.brought_in(CADDYFILE) is None


@pytest.mark.parametrize(
    "line",
    [
        '\trespond /a "a text of one line, with a # and a { in it" 200\n',
        '\theader X-Empty ""\n',
        '\t# in a comment anything may stand: a " alone, a ` alone, a << and a \\ at its end \\\n',
        "\trespond /b 200 # a note after what a line says, which Caddy takes for a comment too\n",
    ],
)
def test_one_word_in_quotes_and_whatever_a_comment_holds_leave_a_caddyfile_plain(line: str) -> None:
    assert TRY.plain(with_a_line(line)) is None


@pytest.mark.parametrize(
    ("line", "why"),
    [
        ("\trespond /a \\\n\t\t200\n", "a backslash"),
        # After such a note the next line is one with this one for Caddy: the two are no longer two lines.
        ("\trespond /a 200 # a note \\\n", "a backslash"),
        ('\trespond /a "one\n\t# two\n\tthree" 200\n', 'a " that is not around one whole word of one line'),
        ('\tpath_regexp a"b "c\n', 'a " that is not around one whole word of one line'),
        ('\trespond "a""b"\n', 'a " that is not around one whole word of one line'),
        ('\trespond a"b\n', 'a " that is not around one whole word of one line'),
        ("\trespond `one\n\ttwo` 200\n", "a ` or a <<"),
        ("\trespond <<TEXT\n\tone\n\tTEXT 200\n", "a ` or a <<"),
        # Also where it would join nothing and open nothing: this tool does not read a line word by word.
        ("\tpath_regexp \\.css$\n", "a backslash, and this tool takes none"),
        # After this one the quote does not close its text, which then runs on to the " in the comment below.
        ('\t@a path "a\\" "b " c\n\t# " /hidden\n', "a backslash, and this tool takes none"),
        ('\trespond `{"status":"ok"}` 200\n', "a ` or a <<, and this tool takes neither"),
        ('\trespond {"status":"ok"} 200\n', 'a " that is not around one whole word of one line'),
        ("\trespond /a\x0c200\n", "a character that does not print ('\\x0c')"),
        ("\t# a comment\u2028\trespond /a 200\n", "a character that does not print ('\\u2028')"),
        ("\trespond /a 200\r\n", "a character that does not print ('\\r')"),
    ],
)
def test_a_caddyfile_whose_lines_do_not_stand_by_themselves_is_not_plain(line: str, why: str) -> None:
    found = TRY.plain(with_a_line(line))
    assert found is not None and found.startswith(why), found


@pytest.mark.parametrize(
    ("line", "why"),
    [
        # Caddy fills this in before it reads the file: the next } of the file goes with it, and a block stays open.
        ("\t# {$Z:\n", "a {$ in a comment, which Caddy fills in there as anywhere, up to the next }: # {$Z:"),
        ("\t# {$Z\n", "a {$ in a comment"),
        ("\t  # set {$ISSUER_HOST} in deploy/.env\n", "a {$ in a comment"),
        ("\trespond /a {$STATUS\n", "a {$ that does not end on its line as {$NAME} or {$NAME:default} does: respond"),
        ("\trespond /a 200 # as {$Z: says\n", "a {$ that does not end on its line"),
        ("\trespond /a {$} 200\n", "a {$ that does not end on its line"),
        ("\trespond /a {$A:{$B}} 200\n", "a {$ that does not end on its line"),
        ("\trespond /a {$1} 200\n", "a {$ that does not end on its line"),
        ("\trespond /a {$A-B} 200\n", "a {$ that does not end on its line"),
        ("\trespond /a {$A:{b} 200\n", "a {$ that does not end on its line"),
    ],
)
def test_a_name_from_the_environment_stands_in_no_comment_and_ends_on_its_line(line: str, why: str) -> None:
    found = TRY.plain(with_a_line(line))
    assert found is not None and found.startswith(why), found
    assert TRY.said(with_a_line("\t# {$Z:\n")) == TRY.said(CADDYFILE), "what such a comment says is not in the digest"


@pytest.mark.parametrize(
    "line",
    [
        "\treverse_proxy {$PID_UPSTREAM:cunho-pid:8000}\n",
        "\trespond /a {$A}{$B_2:x y} 200 # a note with {$A} in it, after what the line says\n",
        "\trespond /a {$_a:} 200\n",
        "\t# a comment with a { and a $ and a } in it, and with {args[0]}\n",
        "\tx#{$A} 200\n",  # a # in the middle of a word begins no comment, whatever the word begins with
    ],
)
def test_a_name_from_the_environment_that_ends_on_its_line_leaves_a_caddyfile_plain(line: str) -> None:
    assert TRY.plain(with_a_line(line)) is None


def test_a_byte_order_mark_is_a_character_that_does_not_print() -> None:
    found = TRY.plain("\ufeff" + CADDYFILE)
    assert found is not None and "does not print" in found


@pytest.mark.parametrize(
    "line",
    [
        "\timport /etc/caddy/more/*.caddy\n",
        "\timport more.caddy\n",
        "\timport tls_policy with an argument\n",
        "\timport\n",
        '\t"import" more.caddy\n',
        "\timport no_such_snippet\n",
    ],
)
def test_a_file_brought_in_is_seen_and_a_snippet_of_the_caddyfiles_own_is_not(line: str) -> None:
    assert TRY.brought_in(with_a_line(line)) == line.strip()
    assert TRY.brought_in(with_a_line("\timport tls_policy\n\t# import more.caddy\n\trespond /import 200\n")) is None
    assert TRY.brought_in(with_a_line("\timportx more.caddy\n\tximport more.caddy\n")) is None, "other words"


@pytest.mark.parametrize(
    "opened",
    [
        "(headers)  {",
        "(headers)\t{",
        "(headers) { ",
        "(headers) {\t",
        "(headers) { # on every answer",
        "(headers) {\t#",
    ],
)
def test_a_snippet_is_known_by_its_line_however_the_brace_is_spaced_and_whatever_note_follows(opened: str) -> None:
    assert CADDYFILE.count("\n(headers) {\n") == 1
    assert TRY.brought_in(CADDYFILE.replace("\n(headers) {\n", f"\n{opened}\n")) is None


@pytest.mark.parametrize(
    "opened",
    # No brace of its own, a note that is no note, not at the start of its line, or another name.
    [
        "(headers){",
        "(headers) {#",
        "(headers) {# a note",
        "(headers) { x",
        " (headers) {",
        "(headers ) {",
        "(header) {",
    ],
)
def test_a_line_that_opens_no_snippet_for_caddy_opens_none_here(opened: str) -> None:
    assert TRY.brought_in(CADDYFILE.replace("\n(headers) {\n", f"\n{opened}\n")) == "import headers"


@pytest.mark.parametrize("name", ["conf.d/*", "/data/more", "more.caddy", "{$MORE}", "a*", "caf\u00e9", "a,b"])
def test_a_name_that_could_be_a_path_is_not_taken_for_a_snippets(name: str) -> None:
    """Caddy takes `import name` for a file when it holds no snippet of that name, and it holds none for a snippet
    that stands inside another one. Such a name could then bring in a file that is here on one machine and not on
    another, and a plain name cannot: it is looked for beside the Caddyfile alone."""
    inside = f"(outer) {{\n({name}) {{\n\trespond 200\n}}\n}}\n"
    assert TRY.brought_in(inside + with_a_line(f"\timport {name}\n")) == f"import {name}"
    plainly = "(outer) {\n(more-of_1) {\n\trespond 200\n}\n}\n"
    assert TRY.brought_in(plainly + with_a_line("\timport more-of_1\n")) is None


def changed(old: str, new: str) -> str:
    assert COMPOSE.count(old) == 1, old
    return COMPOSE.replace(old, new)


def test_the_service_gives_the_image_by_its_digest() -> None:
    image = TRY.service(COMPOSE)
    assert image.startswith("caddy@sha256:") and image.removeprefix("caddy@") in COMPOSE
    assert ":2." not in image, "the tag is left out: the digest alone says which image"
    elsewhere = changed("    image: caddy:2.11.9@", "    image: registry.example:5000/library/caddy:2.11.9@")
    assert TRY.service(elsewhere) == "registry.example:5000/library/" + image, "a port is no tag"
    assert TRY.service(changed("    image: caddy:2.11.9@", "    image: caddy@")) == image


@pytest.mark.parametrize(
    ("old", "new", "why"),
    [
        (
            "    cap_add: [NET_BIND_SERVICE]\n",
            "    cap_add: [NET_BIND_SERVICE]\n    command: caddy run --config /etc/caddy/other\n",
            "has command, which this tool does not know how to try",
        ),
        (
            "    cap_add: [NET_BIND_SERVICE]\n",
            "    cap_add: [NET_BIND_SERVICE]\n    entrypoint: [caddy, reverse-proxy]\n",
            "has entrypoint, which",
        ),
        *(
            (
                "    cap_add: [NET_BIND_SERVICE]\n",
                f"    cap_add: [NET_BIND_SERVICE]\n    {line}\n",
                f"has {line.split(':')[0]}, which this tool does not know how to try",
            )
            for line in (
                "env_file: ./caddy.env",
                "configs: [caddyfile]",
                "secrets: [caddyfile]",
                "extends: {service: demo}",
                "volumes_from: [demo]",
                "<<: *hardened",
                "tmpfs: [/etc/caddy]",
                "working_dir: /srv",
                "user: root",
                "network_mode: host",
                "extra_hosts: [cunho-pid=192.0.2.1]",
                "healthcheck: {test: [CMD, caddy, reload]}",
                '"command": caddy run',
            )
        ),
        ("    cap_add: [NET_BIND_SERVICE]\n", "    cap_add: [NET_BIND_SERVICE]\n    cap_add: [ALL]\n", "cap_add twice"),
        ("@sha256:0c2243ef", ":latest#0c2243ef", "not written as a name and a digest"),
        (
            "    cap_add: [NET_BIND_SERVICE]\n",
            "    cap_add: [NET_BIND_SERVICE]\n    image: caddy:latest\n",
            "image twice",
        ),
        (
            "- ./Caddyfile:/etc/caddy/Caddyfile:ro",
            "- ./Caddyfile.other:/etc/caddy/Caddyfile:ro",
            "volumes is not what this tool knows, or is not written the way it reads it: - ./Caddyfile.other:",
        ),
        ("- public:/srv/public:ro", "- public:/srv/elsewhere:ro", "volumes is not what this tool knows"),
        (
            "      - caddy-config:/config\n",
            "      - caddy-config:/config\n      - ./more:/etc/caddy/more:ro\n",
            "reads it: - ./more:/etc/caddy/more:ro",
        ),
        ("      - caddy-config:/config\n", "", "reads it: - caddy-config:/config"),
        (
            "      - caddy-data:/data\n      - caddy-config:/config\n",
            "      - caddy-config:/config\n      - caddy-data:/data\n",
            "the order of its lines",
        ),
        ("- public:/srv/public:ro\n", "- public:/srv/public:ro # the CRL\n", "volumes is not what"),
        (
            "      DEMO_HOST: ${DEMO_HOST}\n",
            "      DEMO_HOST: ${DEMO_HOST}\n      GODEBUG: http2debug=2\n",
            "environment is not what this tool knows, or is not written the way it reads it: GODEBUG: http2debug=2",
        ),
        ("      ISSUER_HOST: ${ISSUER_HOST}\n", "      ISSUER_HOST: issuer.example\n", "environment is not what"),
        ("      DEMO_HOST: ${DEMO_HOST}\n", "      - DEMO_HOST=${DEMO_HOST}\n", "environment is not what"),
        ("      DEMO_HOST: ${DEMO_HOST}\n", "", "reads it: DEMO_HOST: ${DEMO_HOST}"),
    ],
)
def test_a_service_that_starts_caddy_another_way_is_not_tried_by_halves(old: str, new: str, why: str) -> None:
    with pytest.raises(TRY.CannotTry) as refused:
        TRY.service(changed(old, new))
    assert why in str(refused.value)


def test_how_the_container_is_bounded_and_named_changes_nothing_of_what_is_tried() -> None:
    more = (
        "    mem_limit: 256m\n    mem_reservation: 64m\n    cpus: 0.5\n    pids_limit: 200\n"
        "    labels:\n      app.part: edge\n    container_name: cunho-caddy\n    stop_grace_period: 20s\n"
    )
    bounded = changed("    cap_add: [NET_BIND_SERVICE]\n", f"    cap_add: [NET_BIND_SERVICE]\n{more}")
    assert TRY.service(bounded) == TRY.service(COMPOSE)
    assert TRY.digests(CADDYFILE, bounded)[TRY.SERVICE] != TRY.digests(CADDYFILE, COMPOSE)[TRY.SERVICE]


def test_the_mounts_may_be_the_last_thing_the_service_says() -> None:
    last = "    networks: [internal, edge]\n    logging: *logging\n    depends_on: [demo]\n"
    assert TRY.service(changed(last, "")) == TRY.service(COMPOSE)


def test_a_compose_file_without_a_caddy_service_cannot_be_tried() -> None:
    with pytest.raises(TRY.CannotTry, match="no caddy service"):
        TRY.service(COMPOSE.replace("\n  caddy:\n", "\n  edge:\n"))


@pytest.mark.parametrize("written", ["", "    volumes: [./Caddyfile:/etc/caddy/Caddyfile:ro, public:/srv/public:ro]\n"])
def test_a_service_whose_mounts_are_not_a_list_of_lines_is_refused_and_not_misread(written: str) -> None:
    mounts = "    volumes:\n" + "".join(f"      {mount}\n" for mount in TRY.MOUNTS)
    with pytest.raises(
        TRY.CannotTry, match="volumes is not what this tool knows.*: - ./Caddyfile:/etc/caddy/Caddyfile:ro"
    ):
        TRY.service(changed(mounts, written))


def test_the_stacks_compose_file_reads_here_as_it_reads_to_compose() -> None:
    assert TRY.misread(COMPOSE) is None


@pytest.mark.parametrize(
    ("old", "new", "why"),
    [
        (
            "    restart: unless-stopped\n    cap_drop",
            "    restart: unless-stopped\u2028    command: x\n    cap_drop",
            "a character that does not print ('\\u2028')",
        ),
        ("\nservices:\n", "\nservices: {}\nservices:\n", "a key twice at its top"),
        ("\nservices:\n", "\nx-old: |\n  caddy:\n    image: caddy:1\nservices:\n", "a block of text at its top"),
        ("\nservices:\n", "\nx-old: &old |\n  caddy:\n    image: caddy:1\nservices:\n", "a block of text at its top"),
        ("\nservices:\n", "\nx-old: !!str >-\n  some text\nservices:\n", "a block of text at its top"),
        ("\nservices:\n", "\n'x-old': |\n  some text\nservices:\n", "a block of text at its top"),
        ("\nservices:\n", "\nx-old:\t>\n  some text\nservices:\n", "a block of text at its top"),
        ("\nservices:\n", "\nthe-services:\n", "no services where this tool looks for them"),
        (
            "\n  caddy:\n",
            "\n  caddy :\n    image: other\n  caddy:\n",
            "a service's name twice, or written as a question",
        ),
        (
            "\n  caddy:\n",
            "\n  ? caddy\n  : image: other\n  caddy:\n",
            "a service's name twice, or written as a question",
        ),
        ("\n  caddy:\n", "\n  demo:\n    image: other\n  caddy:\n", "a service's name twice, or written as a question"),
        (
            "\nservices:\n",
            "\nx-old:\n  caddy:\n    image: caddy:1\nservices:\n",
            "the caddy service not once and only once",
        ),
    ],
)
def test_a_compose_file_that_yaml_reads_otherwise_than_its_lines_look_is_refused(old: str, new: str, why: str) -> None:
    assert COMPOSE.count(old) == 1, old
    assert TRY.misread(COMPOSE.replace(old, new)) == why


OPEN = "left open at its end, by a quote or a bracket, or written so that it cannot be told"


@pytest.mark.parametrize(
    "line",
    [
        '    ports: ["${HTTPS_PORT:-443}:${HTTPS_PORT:-443}", "${HTTP_PORT:-80}:80"]',
        '  CUNHO_REDIRECT_URIS: ${REDIRECT_URIS:-{"https://w.test":["https://w.test/cb"]}}',
        "        --forwarded-allow-ips '*' --no-access-log",
        "    restart: unless-stopped # Caddy's own, and a [ in a note",
        "    labels: {a: 'it''s', \"b\": [c, 'd'], ? e : f}",
        "    image: caddy#not-a-note",
        "    container_name: it's",  # a quote that begins nothing is a character like any other
        '    container_name: 5" pipe',
        "    command: a[b] c}d",  # and so is a bracket outside brackets
        "    logging: *logging",
        "x-logging: &logging",
        "    container_name: !!str 'caddy'",
        '    - - "a"',
        "    'key': \"value\"",
        '    ? "a key"',
        "",
        "    labels: []",
        "    container_name: 'a'''",  # the text a', whose own quote is written twice, and then the quote that ends it
        "# a: [b,",  # a note from its first character on
        # What begins nothing in the middle of a plain text, and is a character of it there.
        "    command: a[b",
        "    command: x [a, b",
        '    command: echo a, "b',  # a comma outside brackets
        "    image: caddy:'2",  # a colon with no blank after it
        "    command: -'a",  # a dash with no blank after it
        "    command: ?'a",  # a question mark with none
        "    command: :'a",  # and a colon with none begin a plain text, as any letter does
        "    command: a ]",
        "    command: a, b",
        # Inside brackets: plain texts of letters, digits and a few signs, with a colon in them or after them.
        "    ports: [80:80, 443:443]",
        "    test: [CMD, wget, -qO-, http://localhost:2019/config/]",
        "    labels: {a.b: c=d, e_f: $G}",
        "    labels: [caf\u00e9]",
        "    labels: [ a , b ]\t",
        '    labels: {"a":"b", \'c\':[d]}',
        "    labels: [? a : b]",  # a key written out, which every reader takes for one there
        "    <<: [*one, *two]",
        "    labels: [&a b, *a]",
        "    logging: *logging # a note",
        # A # right after a bracket or a text in quotes begins a note for YAML, with no blank before it.
        "    labels: [a]# and a ] in the note",
        "    container_name: 'a'# and a ' in the note",
        "    labels: [a]: b",  # brackets may be a key
        "    labels: {a: b}  ",
        "    : a",  # and a value may have no key
        "    'a key':",
        "    restart: unless-stopped # a note: 'and so on",  # after a blank, a # ends a plain text as well
    ],
)
def test_a_line_that_closes_what_it_opens_is_not_left_open(line: str) -> None:
    assert TRY.left_open(line) == (False, None)


@pytest.mark.parametrize(
    "line",
    [
        '    labels: ["a=b",',
        "    labels: {a: b,",
        '    container_name: "caddy',
        "    container_name: 'caddy",
        '    labels: ["]"',
        "    labels: ['a', \"b]",
        "    labels: [a, # ]",
        "    - 'a",
        "    ? 'a",
        '"a',
        # Where YAML takes a quote for the beginning of a text, however it is led up to.
        '    labels: [a", "x]',  # the first is a character of the word a", the second begins a text
        "    container_name: 'a''",  # two of them inside a text are one of them: the text is not ended
        '    labels: {"a":"b}',  # a value right after a key in quotes, inside brackets
        '    container_name: !!str "a',
        '    container_name: &name "a',
        '    labels: [? "a',
        '    labels: [a: "b',
        '    labels: [&a "b',
        '    "key": "value',
        "    - - [",
        # A #, an & or a ! in the middle of a word is a character of the word: what follows the word is read.
        "a#b: [c,",
        "    box#1: [a,",
        "    a&b: 'c",
        "    labels: [a [b]",  # inside brackets every bracket counts, wherever it stands
        "    command: [xcaddy, run,",
        '    container_name:\t"caddy',  # a tab after the colon is a blank
        "    -\t'a",  # and after the dash
        # A # that follows a bracket, a comma or a text in quotes begins a note, and the ] or } in it closes nothing.
        "    labels: [#]",
        "    labels: [# ]",
        "    labels: [a=b,#]",
        "    labels: {a: [b]#}",
        "    labels: ['a'# ]",
        # Inside brackets a ? where a thing may begin is a key written out, whatever follows it.
        "    labels: [?#}",
        "    labels: [?']",
    ],
)
def test_a_line_that_ends_inside_quotes_or_brackets_is_left_open(line: str) -> None:
    assert TRY.left_open(line) == (True, None)


@pytest.mark.parametrize(
    "line",
    [
        # Inside brackets, in a plain text: what one reader of YAML ends the text at and another does not, or
        # what is an error for one and a character for another.
        "    labels: [a?b]",
        "    labels: [a#b]",
        "    labels: [it's]",
        "    labels: [a|b]",
        "    labels: {a:}",
        "    labels: [*a:b]",
        "    labels: [|]",
        "    labels: [!!str a]",
        "    labels: [- 'a']",
        # After a text in quotes, brackets or an alias, anything but a colon or, inside brackets, a comma or their end.
        "    'a' 'b'",
        "    container_name: 'a' b",
        "    container_name: 'a':b",
        "    labels: [a] b",
        "    labels: [a] [",
        "    labels: [[a] [b]]",
        "    labels: ['a' 'b']",
        "    labels: ['a' x]",
        "    logging: *logging x",
        # An anchor, an alias or a tag whose name one reader may end sooner than another.
        "    container_name: !a[b] c",
        "    container_name: !a[b]",
        "    logging: *a] b",
        "    container_name: &a'b c",
        "    container_name: &a?b |",  # one reader ends the name at the ?, and reads a plain text from there
        "    logging: *a.b",
        "    'a' |",
        # A comma or a closing bracket where a thing may begin, outside brackets.
        "    command: ]",
        "    command: }x",
        "    command: , a",
    ],
)
def test_a_line_of_which_it_cannot_be_told_is_called_open(line: str) -> None:
    """YAML itself refuses most of these, some of its readers only once they have read on: a reader that is read
    on from such a line is what this guards against, so the line is not called closed."""
    assert TRY.left_open(line) == (True, None)


@pytest.mark.parametrize(
    ("line", "belongs_to"),
    [
        ("    command: |", 4),
        ("    command: >-  # folded", 4),
        ("    - |", 4),
        ("    - name: |2", 6),  # the text belongs to the name, which stands further in than the dash
        ("    - - >", 6),
        ("    command: !!str |", 13),  # no less far in than the tag: the text belongs to what the tag stands before
        ("      !!str |", 6),  # on a line of its own, under the key it is the value of
        ("      &text |", 6),
        ("      >-", 6),
        ("    ? |", 4),
        ("  'a key': |+", 2),
        ("    - 'a key': |", 6),
        ("    - x-note: |", 6),
        ("    a - b: |", 4),  # a dash in the middle of a key is a character of the key
        # A key in brackets begins where the brackets do, whatever stands inside them.
        ("    [a, 'b']: |", 4),
        ("    [&a b, c]: |", 4),
        ("    - {a: b}: |", 6),  # after a dash as well
        ("    - [a]: >", 6),
        ("    - *a : |", 6),
        ("    - : |", 6),  # with no key, the text belongs to where the colon stands
        ("    : |", 4),
        ("    [[a], b]: |", 4),
        ("    [: a]: |", 4),
        ("    [? a : b]: |", 4),
    ],
)
def test_a_line_that_opens_a_block_of_text_says_how_far_in_the_text_belongs(line: str, belongs_to: int) -> None:
    assert TRY.left_open(line) == (False, belongs_to)
    for no_block in ("    labels: # x: |", "    command: a |", "    command: [a, |]", "    command: '|'", "    a|"):
        assert TRY.left_open(no_block)[1] is None, no_block


@pytest.mark.parametrize(
    ("more", "why"),
    [
        # The value goes on at the left: read by indent alone, the service ended there, and the command was not seen.
        (
            '    labels: ["a=b",\n"c=d"]\n    command: [caddy, file-server]\n',
            "left open at its end, by a quote or a bracket",
        ),
        ("    labels: {a: b,\n  c: d}\n    command: [caddy, file-server]\n", "left open at its end"),
        ('    container_name: "caddy\n"\n    command: [caddy, file-server]\n', "left open at its end"),
        ("    container_name: 'caddy\n  '\n    command: [caddy, file-server]\n", "left open at its end"),
        ('    container_name: "a\\"\n    command: [caddy, file-server]\n', "a backslash in"),
        # Ways round a count of quotes and brackets, each of them YAML that reads as it is said here.
        (
            '    labels: # x: |\n      ["a\nb", "c\n    x: y # y: |\n      d"]\n    command: [evil]\n',
            "left open at its end",
        ),
        ('    labels: [a", "x]\ny"] # "\n    command: [evil]\n', "left open at its end"),
        ("    container_name: 'a''\nb' # '\n    command: [evil]\n", "left open at its end"),
        ('    labels: {"a":"b}\nc"} # "\n    command: [evil]\n', "left open at its end"),
        ('    container_name: !!str "a\nb"\n    command: [evil]\n', "left open at its end"),
        ('    labels:\n    - name: |\n      other: "x\ny" # "\n    command: [evil]\n', "left open at its end"),
        ('    x#1: "a\nb"\n    command: [evil]\n', "left open at its end"),  # a key with a # in it is no note
        # A # right after a bracket, a comma or a text in quotes is a note for YAML: the ] after it closes nothing.
        ('    labels: [# ]\n"c=d"]\n    command: [evil]\n', "left open at its end"),
        ('    labels: [a=b,#]\n"c=d"]\n    command: [evil]\n', "left open at its end"),
        ("    labels: {a: [b]#}\n}\n    command: [evil]\n", "left open at its end"),
        ("    labels: ['a=b'# ]\n, \"c=d\"]\n    command: [evil]\n", "left open at its end"),
        ("    labels: [?#}\nx]\n    command: [evil]\n", "left open at its end"),
        # A block of text that belongs to a key in brackets after a dash: the line under that key is no text.
        (
            '    labels:\n    - {a: b}: |\n        text\n      x: "open\ny"\n    command: [evil]\n',
            "left open at its end",
        ),
    ],
)
def test_a_line_of_the_compose_file_left_open_at_its_end_is_refused(more: str, why: str) -> None:
    for old in ("    cap_add: [NET_BIND_SERVICE]\n", "    depends_on: [cunho-pid, cunho-course]\n"):  # in any service
        file = changed(old, old + more)
        found = TRY.misread(file)
        assert found is not None and why in found, found
        told = int(found.split("line ")[1].split()[0])
        first = file.split("\n").index(more.split("\n")[0]) + 1
        assert first <= told < first + more.count("\n"), "the line it names is one of those put in"
    hidden = changed("    depends_on: [demo]\n", "    depends_on: [demo]\n" + more)
    assert TRY.misread(hidden) is not None
    if "backslash" not in why:  # after a quote that a backslash keeps open, the command is text for YAML
        assert "command" not in TRY.block(hidden, "caddy:", "  "), "which is what the line at the left did"


def test_a_text_left_open_in_another_service_cannot_take_the_caddy_service_with_it() -> None:
    """For YAML the lines of the caddy service would be a part of that text, and the service another one, written
    further down under a name the tool does not take for it."""
    opened = changed(
        "    depends_on: [cunho-pid, cunho-course]\n", '    depends_on: [cunho-pid, cunho-course]\n    x: "demo\n'
    )
    other = opened.replace(
        "\nnetworks:\n", '\nx"\n  !!str caddy:\n    image: other\n    command: [evil]\n\nnetworks:\n'
    )
    assert other != opened and TRY.service(other) == TRY.service(COMPOSE), "read by its lines alone, it is the same"
    number = other.split("\n").index('    x: "demo') + 1
    assert TRY.misread(other) == f"line {number} {OPEN}"


@pytest.mark.parametrize("marked", ["---\n{}", "{}---\n", "{}...\n", "--- # the stack\n{}", "{}---\nservices: {{}}\n"])
def test_a_compose_file_of_more_than_one_document_is_refused(marked: str) -> None:
    file = marked.format(COMPOSE)
    number = next(n for n, line in enumerate(file.split("\n"), 1) if line.startswith(("---", "...")))
    assert TRY.misread(file) == f"more than one document, or the end of one, at line {number}"
    assert TRY.misread(COMPOSE.replace("\nservices:\n", "\n# --- the services ---\nservices:\n")) is None


def test_the_lines_of_a_block_of_text_are_text_whatever_they_hold() -> None:
    script = (
        "    healthcheck:\n      test: |\n        echo \"it's [open\n\n          and 'more \\\n      interval: 30s\n"
    )
    file = changed(
        "    depends_on: [cunho-pid, cunho-course]\n", "    depends_on: [cunho-pid, cunho-course]\n" + script
    )
    assert TRY.misread(file) is None
    # Where the text ends, lines are lines again.
    after = file.replace("      interval: 30s\n", '      interval: "30s\n')
    number = after.split("\n").index('      interval: "30s') + 1
    assert TRY.misread(after) == f"line {number} {OPEN}"
    # And in a comment anything may stand, as in the Caddyfile: a backslash, a quote alone, a bracket.
    noted = changed("    depends_on: [demo]\n", '    depends_on: [demo]\n    # C:\\caddy, "quoted, [and so on\n\n')
    assert TRY.misread(noted) is None
    last = "    depends_on: [cunho-pid, cunho-course]\n"
    folded = changed(last, f"{last}    labels:\n      - >-  # folded\n        a 'b\n")
    assert TRY.misread(folded) is None
    # A line that stands no further in than what the text belongs to is no line of the text.
    under_its_key = "    x:\n      !!str |"
    for opens, beside in (
        ('    "x": |', '    y: "open'),
        ('    "y": |', '    x-more: "open'),
        ("    - {a: b}: |", '      x: "open'),
        ("    - name: |", '      other: "open'),
        ("    - |", '    - "open'),
        (under_its_key, '    y: "open'),
        (under_its_key.replace("!!str ", ""), '      "open'),
    ):
        last = "    depends_on: [cunho-pid, cunho-course]\n"
        file = changed(last, f"{last}{opens}\n{beside}\n")
        number = file.split("\n").index(beside) + 1
        assert TRY.misread(file) == f"line {number} {OPEN}", opens


IN_TEXT = "a block of text in the caddy service, of whose lines a blank one or one that begins with a # is not held"


@pytest.mark.parametrize(
    "more",
    [
        "    container_name: |\n      line-one\n      # a line of the text, and no comment\n\n      line-two\n",
        "    labels:\n      a: >-\n        b\n        # c\n",
        "    labels:\n      - |\n        a=b\n",
        "    labels:\n      a: !!str |\n        b\n",
        "    container_name: caddy\n      | and more\n",  # further in, it goes on with the name: a | begins no text
    ],
)
def test_a_block_of_text_in_the_caddy_service_is_refused(more: str) -> None:
    """Inside a text a line that begins with a # is text for Compose, and a blank line is a line break. What is
    held of the service is its lines without comments and blank lines, so neither would be held: two files that
    Compose reads differently would say the same here."""
    for after in ("  caddy:\n", "    cap_add: [NET_BIND_SERVICE]\n", "    depends_on: [demo]\n"):  # first to last
        assert TRY.misread(changed(after, after + more)) == IN_TEXT
    # And that is why: with the lines of the text that look like comments taken out, the service says the same.
    last = "    depends_on: [demo]\n"
    one = changed(last, last + "    container_name: |\n      a\n      # b\n\n      c\n")
    other = changed(last, last + "    container_name: |\n      a\n      c\n")
    assert TRY.told("", one)[TRY.SERVICE] == TRY.told("", other)[TRY.SERVICE]
    # In another service a block of text is what it was: text, whatever its lines hold.
    elsewhere = "    depends_on: [cunho-pid, cunho-course]\n"
    assert TRY.misread(changed(elsewhere, elsewhere + "    labels:\n      a: |\n        # b\n\n        c\n")) is None


BETWEEN = "a blank line in the caddy service elsewhere than between two of its keys"
ADD = "    cap_add: [NET_BIND_SERVICE]\n"  # a line of the caddy service, and of no other


@pytest.mark.parametrize(
    ("old", "new", "why"),
    [
        # Before a line that goes on with a value, a blank line is a line break in that value.
        (ADD, f"{ADD}    container_name: caddy\n\n      and more\n", BETWEEN),
        (ADD, f"{ADD}    container_name: caddy\n\n      # a note\n      and more\n", BETWEEN),
        ("      ISSUER_HOST: ${ISSUER_HOST}\n", "\n      ISSUER_HOST: ${ISSUER_HOST}\n", BETWEEN),
        ("      - caddy-data:/data\n", "      - caddy-data:/data\n   \t\n", BETWEEN),
        # Between two keys of the service it says nothing, with or without a comment beside it.
        (ADD, f"{ADD}\n", None),
        (ADD, f"{ADD}\n    # a note\n\n", None),
        (ADD, f"{ADD}      # a note, further in\n", None),
        (ADD, f"{ADD}\n      # a note, further in\n\n# and one at the left\n", None),
        ("    depends_on: [demo]\n", "    depends_on: [demo]\n\n\n", None),
        # Lines that go on with a value and have no blank line among them are held as the lines they are.
        (ADD, f"{ADD}    container_name: caddy\n      x\n      y\n", None),
        (ADD, f"{ADD}    container_name: caddy\n\n      x#1\n", BETWEEN),  # which is no comment
    ],
)
def test_a_blank_line_in_the_caddy_service_stands_only_between_two_of_its_keys(
    old: str, new: str, why: str | None
) -> None:
    assert TRY.misread(changed(old, new)) == why
    # A service written one space further in is not this guard's to refuse: the tool does not start one.
    lines = COMPOSE.split("\n")
    start = lines.index("  caddy:") + 1
    end = next(number for number in range(start, len(lines)) if not lines[number].startswith("    "))
    moved = [f" {line}" for line in lines[start:end] if "*logging" not in line]  # all but the line with the alias
    further = "\n".join(lines[:start] + moved + lines[end:])
    assert TRY.misread(further) is None
    with pytest.raises(TRY.CannotTry, match="image is not written as a name and a digest"):
        TRY.service(further)


def test_what_the_caddy_service_takes_by_an_alias_is_held_with_it() -> None:
    """`logging: *logging` says nothing by itself: what it stands for is written above the services, for all of
    them. Compose reads it into the caddy service, so it is held with the service's lines."""
    other = changed("    max-size: 10m\n", "    max-size: 1k\n")
    assert TRY.misread(other) is None
    assert TRY.told("", other)[TRY.SERVICE].endswith('    max-size: 1k\n    max-file: "3"\n')
    assert TRY.digests(CADDYFILE, other)[TRY.SERVICE] != TRY.digests(CADDYFILE, COMPOSE)[TRY.SERVICE]
    assert TRY.service(other) == TRY.service(COMPOSE), "the service's own lines are read as before"
    # A comment in that block, or a blank line between two of its keys, says nothing.
    noted = changed("  options:\n", "\n  # how much of it is kept\n  options:\n")
    assert TRY.misread(noted) is None
    assert TRY.told("", noted)[TRY.SERVICE] == TRY.told("", COMPOSE)[TRY.SERVICE]
    # What else stands above the services is no part of it.
    elsewhere = changed("x-hardened: &hardened\n  read_only: true\n", "x-hardened: &hardened\n  read_only: false\n")
    assert TRY.misread(elsewhere) is None
    assert TRY.told("", elsewhere)[TRY.SERVICE] == TRY.told("", COMPOSE)[TRY.SERVICE]
    # A note after the alias is a note.
    after = changed("    logging: *logging\n", "    logging: *logging  # as all the services\n")
    assert TRY.misread(after) is None and TRY.told("", after)[TRY.SERVICE].endswith(SHARED)


NO_ALIAS = "a * in the caddy service that is no alias for the whole value of one of its keys: "
NO_BLOCK = "an alias in the caddy service, *{}, that stands for no one block of its own at the top"
THEIRS = "the block that *logging stands for"


@pytest.mark.parametrize(
    ("old", "new", "why"),
    [
        # An alias elsewhere than as the whole value of one of the service's keys, or a * that could be one.
        ("    networks: [internal, edge]\n", "    networks: [*nets]\n", NO_ALIAS + "networks: [*nets]"),
        ("    logging: *logging\n", "    logging:\n      <<: *logging\n", NO_ALIAS + "<<: *logging"),
        ("    logging: *logging\n", "    logging: &mine *logging\n", NO_ALIAS + "logging: &mine *logging"),
        (ADD, f"{ADD}    container_name: a*b\n", NO_ALIAS + "container_name: a*b"),
        (
            "    depends_on: [demo]\n",
            "    depends_on: [demo]\n    container_name: a*b\n",
            NO_ALIAS + "container_name: a*b",
        ),
        # An alias that stands for no block of its own at the top, or for more than one.
        ("    logging: *logging\n", "    logging: *nowhere\n", NO_BLOCK.format("nowhere")),
        ("x-logging: &logging\n", "x-logging: &logging  # for all of them\n", NO_BLOCK.format("logging")),
        ("x-logging: &logging\n", "x-logging: &logging {driver: none}\nx-was:\n", NO_BLOCK.format("logging")),
        (
            "x-logging: &logging\n",
            "x-first: &logging\n  driver: none\nx-logging: &logging\n",
            NO_BLOCK.format("logging"),
        ),
        ("x-hardened: &hardened\n", "x-hardened: &hardened\n  labels: &logging {a: b}\n", NO_BLOCK.format("logging")),
        # The block itself: nothing in it that stands for something else, and all of its lines held.
        ("  driver: json-file\n", "  driver: json-file\n  <<: *more\n", f"an alias, an anchor or a merge in {THEIRS}"),
        ("  options:\n", "  options: &again\n", f"an alias, an anchor or a merge in {THEIRS}"),
        ("  driver: json-file\n", "  <<: {driver: none}\n", f"an alias, an anchor or a merge in {THEIRS}"),
        # A block of text on the block's first line, and on its last.
        (
            "  driver: json-file\n",
            "  driver: |\n    json-file\n",
            f"a block of text in {THEIRS}, of whose lines a blank one or one that begins with a # is not held",
        ),
        (
            '    max-file: "3"\n\n',
            "    max-file: |\n",
            f"a block of text in {THEIRS}, of whose lines a blank one or one that begins with a # is not held",
        ),
        (
            "    max-size: 10m\n",
            "    max-size: |\n      10m\n",
            f"a block of text in {THEIRS}, of whose lines a blank one or one that begins with a # is not held",
        ),
        (
            "    max-size: 10m\n",
            "\n    max-size: 10m\n",
            f"a blank line in {THEIRS} elsewhere than between two of its keys",
        ),
    ],
)
def test_an_alias_in_the_caddy_service_is_one_whole_value_for_one_block_at_the_top(
    old: str, new: str, why: str
) -> None:
    assert TRY.misread(changed(old, new)) == why


def test_a_caddy_service_moved_out_from_among_the_services_is_refused() -> None:
    lines = COMPOSE.split("\n")
    start = lines.index("  caddy:")
    end = next(
        number for number in range(start + 1, len(lines)) if lines[number] and not lines[number].startswith("   ")
    )
    moved = "\n".join(lines[:start] + lines[end:] + ["x-moved:"] + lines[start:end])
    assert TRY.misread(moved) == "the caddy service not once and only once"
    assert TRY.key("  'caddy' : x") == "caddy" and TRY.key('\t"xbox": {}') == "xbox"
    assert TRY.key("x-logging: &logging") == "x-logging"


def test_a_caddy_service_that_stands_elsewhere_than_among_the_services_is_refused() -> None:
    # Among the services one is named caddy in quotes, and the line this tool looks for stands under another key.
    moved = COMPOSE.replace("\n  caddy:\n", '\n  "caddy":\n') + "x-moved:\n  caddy:\n    image: other\n"
    assert TRY.misread(moved) == "the caddy service elsewhere than among the services"


# Caddy's own reading of the Caddyfile -----------------------------------------------------------------------------

SET = {"Strict-Transport-Security": ["max-age=31536000"], "X-Content-Type-Options": ["nosniff"]}


def lines() -> list[Any]:
    """The two lines of the Caddyfile's snippet, as Caddy reads them."""
    return [
        {"handler": "headers", "response": {"set": copy.deepcopy(SET)}},
        {"handler": "headers", "response": {"deferred": True, "set": copy.deepcopy(SET)}},
    ]


def respond(status: int) -> Any:
    return {"handler": "static_response", "status_code": status}


def proxy(dial: str) -> Any:
    return {"handler": "reverse_proxy", "upstreams": [{"dial": dial}]}


def handle(paths: list[str] | None, group: str, *handlers: Any) -> Any:
    """A handle block: its lines stand in a subroute of their own, and it shares a group with its neighbours."""
    inner = {"handler": "subroute", "routes": [{"handle": list(handlers)}]}
    made: dict[str, Any] = {"group": group, "handle": [inner]}
    if paths is not None:
        made["match"] = [{"path": paths}]
    return made


def served(path: str, group: str, root: str, file: str, kind: str, rewrites: str) -> Any:
    """A handle block that serves one file under a path."""
    kinds = {"handler": "headers", "response": {"set": {"Content-Type": [kind]}}}
    inner = [
        {"handle": [{"handler": "vars", "root": root}, kinds]},
        {"group": rewrites, "handle": [{"handler": "rewrite", "uri": file}]},
        {"handle": [{"handler": "file_server", "hide": ["/etc/caddy/Caddyfile"]}]},
    ]
    return {"group": group, "handle": [{"handler": "subroute", "routes": inner}], "match": [{"path": [path]}]}


def site(host: str, *routes: Any) -> Any:
    whole = [{"handle": lines()}, *routes]
    return {"match": [{"host": [host]}], "handle": [{"handler": "subroute", "routes": whole}], "terminal": True}


def errors_of(host: str) -> Any:
    inner = {"handler": "subroute", "routes": [{"handle": lines()}]}
    outer = {"handler": "subroute", "routes": [{"handle": [inner]}]}
    return {"match": [{"host": [host]}], "handle": [outer], "terminal": True}


def reading() -> Any:
    """What Caddy 2.11.9 makes of the stack's Caddyfile: what `caddy adapt` gave for it with these two host names."""
    issuers, servers = "/.well-known/openid-credential-issuer", "/.well-known/oauth-authorization-server"
    issuer = site(
        HOSTS["issuer"],
        handle(["/pid/admin", "/pid/admin/*", "/course/admin", "/course/admin/*"], "group9", respond(404)),
        served("/crl/iaca.crl", "group9", "/srv/public", "/iaca.crl", "application/pkix-crl", "group2"),
        handle(["/pid", "/pid/*", f"{issuers}/pid", f"{servers}/pid"], "group9", proxy("cunho-pid:8000")),
        handle(
            ["/course", "/course/*", f"{issuers}/course", f"{servers}/course"], "group9", proxy("cunho-course:8000")
        ),
        handle(None, "group9", respond(404)),
    )
    metadata = ("/srv/type_metadata", "/course-certificate-1.json", "application/json")
    demo = site(
        HOSTS["demo"],
        served("/vct/course-certificate/1", "group11", *metadata, "group7"),
        handle(None, "group11", proxy("demo:8000")),
    )
    sizes = ("128_GCM_SHA256", "256_GCM_SHA384")
    policy = {
        "match": {"sni": list(HOSTS.values())},
        "cipher_suites": [f"TLS_ECDHE_{key}_WITH_AES_{size}" for key in ("ECDSA", "RSA") for size in sizes],
        "protocol_min": "tls1.2",
        "protocol_max": "tls1.3",
    }
    server = {
        "listen": [":443"],
        "read_timeout": 30000000000,
        "read_header_timeout": 10000000000,
        "idle_timeout": 120000000000,
        "routes": [issuer, demo],
        "errors": {"routes": [errors_of(HOSTS["issuer"]), errors_of(HOSTS["demo"])]},
        "tls_connection_policies": [policy, {}],
        "protocols": ["h1", "h2"],
    }
    return {
        "admin": {"disabled": True},
        "logging": {"logs": {"default": {"exclude": ["http.log.error", "http.handlers.reverse_proxy"]}}},
        "apps": {"http": {"servers": {"srv0": server}}},
    }


def server_of(config: Any) -> Any:
    return config["apps"]["http"]["servers"]["srv0"]


def routes_of(config: Any, host: int) -> Any:
    """The routes inside a host's site block: the snippet's two lines first, then its handle blocks."""
    return server_of(config)["routes"][host]["handle"][0]["routes"]


def snippet_of(config: Any, host: int) -> Any:
    return routes_of(config, host)[0]["handle"]


def errors_in(config: Any, host: int) -> Any:
    """The routes inside a host's error block: one, with the snippet's two lines in a subroute of their own."""
    return server_of(config)["errors"]["routes"][host]["handle"][0]["routes"]


def departing(change: Callable[[Any], Any]) -> list[str]:
    """What is not known to hold of the stack's reading once `change` has been made to it."""
    config = reading()
    change(config)
    found: list[str] = TRY.unknown(config, HOSTS)
    return found


ISSUER, DEMO = 0, 1
ANSWERS_OF_THE_ISSUER = "the answers of the issuer host do not pass the two headers' lines before all else"
ANSWERS_OF_THE_DEMO = "the answers of the demo host do not pass the two headers' lines before all else"
ERRORS_OF_THE_ISSUER = "the errors of the issuer host do not pass the two headers' lines before all else"
ERRORS_OF_THE_DEMO = "the errors of the demo host do not pass the two headers' lines before all else"
ANOTHER_LINE = "another line sets or removes one of the two headers"
NOT_LEFT_OUT = "the log default does not leave out http.handlers.reverse_proxy and http.log.error"
NOT_THE_TWO = "a site block that is not for the two hosts alone, among the answers"


def test_the_stacks_reading_is_known_to_hold() -> None:
    config = reading()
    assert TRY.unknown(config, HOSTS) == []
    assert TRY.access_log(config) is False
    assert TRY.upstreams(config) == [("cunho-course", 8000), ("cunho-pid", 8000), ("demo", 8000)]


def a_header(response: Any) -> Callable[[Any], Any]:
    """Another header line, among the handle blocks of the demo host."""
    return lambda config: routes_of(config, DEMO).insert(1, {"handle": [{"handler": "headers", "response": response}]})


def before_the_lines(route: Any, host: int = ISSUER) -> Callable[[Any], Any]:
    return lambda config: routes_of(config, host).insert(0, route)


def status_is(*statuses: int) -> Any:
    return [{"expression": f"{{http.error.status_code}} in {list(statuses)}"}]


@pytest.mark.parametrize(
    ("change", "whys"),
    [
        # Caddy's own API, and its log.
        (lambda c: c.pop("admin"), ["Caddy's own API is not off"]),
        (lambda c: c.update(admin={"listen": ":2019"}), ["Caddy's own API is not off"]),
        (lambda c: c.pop("logging"), [NOT_LEFT_OUT]),
        (
            lambda c: c["logging"]["logs"]["default"].update(exclude=["http.log.error"]),
            ["the log default does not leave out http.handlers.reverse_proxy"],
        ),
        (
            lambda c: c["logging"]["logs"]["default"].update(exclude=["http.handlers.reverse_proxy"]),
            ["the log default does not leave out http.log.error"],
        ),
        (lambda c: c["logging"]["logs"]["default"].pop("exclude"), [NOT_LEFT_OUT]),
        (
            lambda c: c["logging"]["logs"]["default"].update(level="DEBUG"),
            ["the log default is at the debug level, where Caddy names the client of a connection"],
        ),
        (lambda c: c["logging"]["logs"]["default"].update(level="debug"), ["the log default is at the debug level"]),
        (
            lambda c: c["logging"]["logs"]["default"].update(writer={"output": "file", "filename": "/data/log"}),
            ["the log default is written where this run does not read it (file)"],
        ),
        (
            lambda c: c["logging"]["logs"]["default"].update(writer={"output": "net", "address": "udp/192.0.2.1:514"}),
            ["the log default is written where this run does not read it (net)"],
        ),
        (
            lambda c: c["logging"]["logs"].update(requests={"include": ["http.log.error"]}),
            ["the log requests does not leave out http.log.error"],
        ),
        # Every log is asked about both loggers, and where it is written: a second one as much as the first.
        (
            lambda c: c["logging"]["logs"].update(upstream_errors={"include": ["http.handlers.reverse_proxy"]}),
            ["the log upstream_errors does not leave out http.handlers.reverse_proxy"],
        ),
        (
            lambda c: c["logging"]["logs"].update(
                kept={"exclude": sorted(TRY.LEFT_OUT), "writer": {"output": "file", "filename": "/data/kept.log"}}
            ),
            ["the log kept is written where this run does not read it (file)"],
        ),
        (
            lambda c: c["logging"]["logs"].update(
                sent={"exclude": sorted(TRY.LEFT_OUT), "writer": {"output": "net", "address": "udp/192.0.2.1:514"}}
            ),
            ["the log sent is written where this run does not read it (net)"],
        ),
        (
            lambda c: c["logging"]["logs"].update(more={"exclude": sorted(TRY.LEFT_OUT), "level": "DEBUG"}),
            ["the log more is at the debug level"],
        ),
        # Where Caddy listens, and what it has beside the routes.
        (lambda c: server_of(c).update(listen=[":8443"]), ["Caddy listens at :8443, not at 443 alone"]),
        (lambda c: server_of(c).update(listen=[":443", ":8443"]), ["Caddy listens at :443, :8443, not at 443 alone"]),
        (lambda c: server_of(c).pop("listen"), ["Caddy listens at no address, not at 443 alone"]),
        (
            lambda c: c["apps"]["http"]["servers"].update(srv1={"listen": [":80"], "routes": []}),
            ["Caddy listens at :80, not at 443 alone"],
        ),
        (
            lambda c: server_of(c).update(named_routes={"gate": {"handle": [respond(403)]}}),
            ["Caddy's reading holds apps.http.servers.srv0.named_routes, for which this tool has no rule"],
        ),
        (
            lambda c: server_of(c).update(trusted_proxies={"source": "elsewhere", "interval": 60}),
            ["Caddy's reading holds apps.http.servers.srv0.trusted_proxies.interval, for which this tool has no rule"],
        ),
        # A handler this tool does not know, wherever it stands.
        (
            lambda c: routes_of(c, DEMO).append(handle(["/page"], "group11", {"handler": "encode"})),
            ["(the handler encode), for which this tool has no rule"],
        ),
        (
            lambda c: routes_of(c, DEMO)[2]["handle"][0]["routes"][0]["handle"][0].update(
                handle_response=[{"routes": [{"handle": [{"handler": "copy_response"}]}]}]
            ),
            ["handle_response[0].routes[0].handle[0] (the handler copy_response), for which this tool has no rule"],
        ),
        (
            lambda c: routes_of(c, ISSUER).append({"handle": [{"handler": "invoke", "name": "gate"}]}),
            ["(the handler invoke)"],
        ),
        # Another line for one of the two headers, wherever it stands and however it names the header.
        (a_header({"set": {"Strict-Transport-Security": ["max-age=0"]}}), [ANOTHER_LINE]),
        (a_header({"set": {"x-content-type-options": ["nosniff"]}}), [ANOTHER_LINE]),
        (a_header({"add": {"X-Content-Type-Options": ["nosniff"]}}), [ANOTHER_LINE]),
        (a_header({"delete": ["Strict-Transport-Security"], "deferred": True}), [ANOTHER_LINE]),
        (a_header({"delete": ["strict-*"]}), [ANOTHER_LINE]),
        (a_header({"delete": ["*-Options"]}), [ANOTHER_LINE]),
        (a_header({"delete": ["*"]}), [ANOTHER_LINE]),
        (a_header({"delete": ["{http.request.header.X-Which}"]}), [ANOTHER_LINE]),
        # The name that matters is looked for among all of them, not at the head of the list alone.
        (a_header({"delete": ["Server", "Strict-Transport-Security"], "deferred": True}), [ANOTHER_LINE]),
        (a_header({"set": {"Cache-Control": ["no-store"], "X-Content-Type-Options": ["other"]}}), [ANOTHER_LINE]),
        (a_header({"add": {"Vary": ["Origin"], "Strict-Transport-Security": ["max-age=0"]}}), [ANOTHER_LINE]),
        (
            a_header({"replace": {"Server": [], "X-Content-Type-Options": [{"search": "nosniff", "replace": ""}]}}),
            [ANOTHER_LINE],
        ),
        (
            lambda c: a_proxy(c).update(
                headers={"response": {"delete": ["Server", "X-Powered-By", "Strict-Transport-Security"]}}
            ),
            [ANOTHER_LINE],
        ),
        (
            before_the_lines(
                {
                    "match": [{"header": {"User-Agent": ["*MSIE*"]}}],
                    "handle": [
                        {
                            "handler": "headers",
                            "response": {"deferred": True, "delete": ["Server", "Strict-Transport-Security"]},
                        }
                    ],
                }
            ),
            [ANOTHER_LINE, ANSWERS_OF_THE_ISSUER],
        ),
        (a_header({"set": {"{http.request.header.X-Which}": ["x"]}}), [ANOTHER_LINE]),
        (a_header({"add": {"X-{http.request.uri.query.which}": ["x"]}}), [ANOTHER_LINE]),
        (
            a_header({"replace": {"{http.request.header.X-Which}": [{"search": "max-age", "replace": "min-age"}]}}),
            [ANOTHER_LINE],
        ),
        # Caddy makes a small i of this capital, and so the name is the header's: Python makes two characters of it.
        (a_header({"delete": ["STR\u0130CT-TRANSPORT-SECUR\u0130TY"], "deferred": True}), [ANOTHER_LINE]),
        (a_header({"set": {"X-Content-Type-Opt\u0130ons": ["other"]}}), [ANOTHER_LINE]),
        # In the block for a host's errors too, after the two lines.
        (
            lambda c: errors_in(c, DEMO).append(
                {
                    "handle": [
                        {"handler": "headers", "response": {"delete": ["Strict-Transport-Security"], "deferred": True}}
                    ]
                }
            ),
            [ANOTHER_LINE],
        ),
        (a_header({"replace": {"*": [{"search": "max-age", "replace": "min-age"}]}}), [ANOTHER_LINE]),
        (a_header({"set": copy.deepcopy(SET), "require": {"status_code": [2]}}), [ANOTHER_LINE]),
        (
            a_header({"set": {**SET, "Strict-Transport-Security": ["{http.vars.sts}"]}}),
            ["a line sets strict-transport-security to {http.vars.sts}, not to max-age=31536000"],
        ),
        # The snippet's own two lines, changed.
        (
            lambda c: snippet_of(c, ISSUER)[1]["response"].update(require={"status_code": [2, 4]}),
            [ANOTHER_LINE, ANSWERS_OF_THE_ISSUER],
        ),
        # A line of the snippet that sets one of the two to something else: it is a line of the snippet still, and
        # what is amiss is said of the value, not of the lines or of their place.
        (
            lambda c: snippet_of(c, DEMO)[0]["response"]["set"].update({"Strict-Transport-Security": ["max-age=1"]}),
            ["a line sets strict-transport-security to max-age=1, not to max-age=31536000"],
        ),
        (
            lambda c: [
                line["response"]["set"].update(
                    {"Strict-Transport-Security": ["max-age=31536000; includeSubDomains"], "X-Content-Type-Options": []}
                )
                for host in (ISSUER, DEMO)
                for line in snippet_of(c, host)
            ],
            [
                "a line sets strict-transport-security to max-age=31536000; includeSubDomains, not to max-age=31536000",
                "a line sets x-content-type-options to , not to nosniff",
            ],
        ),
        (
            lambda c: snippet_of(c, DEMO)[1]["response"]["set"].update({"x-content-type-options": "nosniff"}),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],  # the header twice, under two spellings: no line of the snippet
        ),
        (
            lambda c: snippet_of(c, ISSUER)[1]["response"]["set"].update({"X-Content-Type-Options": ["nosniff", "x"]}),
            ["a line sets x-content-type-options to nosniff, x, not to nosniff"],
        ),
        (
            lambda c: snippet_of(c, ISSUER)[0]["response"]["set"].update({"X-Content-Type-Options": "nosniff"}),
            ["a line sets x-content-type-options to nosniff, not to nosniff"],  # a text where Caddy gives a list
        ),
        # One more header beside the two is in order, but not under a name that may turn out to be one of the two,
        # not one of the two a second time, and nothing but setting.
        (
            lambda c: snippet_of(c, DEMO)[1]["response"]["set"].update({"{http.request.header.X-Which}": ["x"]}),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],
        ),
        (
            lambda c: snippet_of(c, DEMO)[0]["response"]["set"].update({"X-Content-Type-Opt\u0130ons": ["other"]}),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],
        ),
        (
            lambda c: snippet_of(c, DEMO)[1]["response"]["set"].update({"strict-transport-security": ["max-age=0"]}),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],
        ),
        (
            lambda c: snippet_of(c, DEMO)[1]["response"]["set"].update(
                {"strict-transport-security": ["max-age=31536000"]}
            ),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],
        ),
        (
            lambda c: snippet_of(c, DEMO)[0]["response"].update(add={"X-Content-Type-Options": ["nosniff"]}),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],
        ),
        (
            lambda c: snippet_of(c, DEMO)[1]["response"].update(add={"X-{http.request.header.X-Which}": ["1"]}),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],
        ),
        (
            lambda c: snippet_of(c, DEMO)[1]["response"].update(delete=["Server", "X-Content-*"]),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],
        ),
        (
            lambda c: snippet_of(c, DEMO)[1]["response"].update(delete=["*"]),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],
        ),
        (
            lambda c: snippet_of(c, DEMO)[0]["response"].update(
                replace={"Cache-Control": [{"search": "private", "replace": "public"}]}
            ),
            [ANOTHER_LINE, ANSWERS_OF_THE_DEMO],
        ),
        (lambda c: snippet_of(c, ISSUER).pop(0), [ANSWERS_OF_THE_ISSUER]),
        (lambda c: snippet_of(c, ISSUER).pop(1), [ANSWERS_OF_THE_ISSUER]),
        (lambda c: snippet_of(c, DEMO).clear(), [ANSWERS_OF_THE_DEMO]),
        (lambda c: snippet_of(c, DEMO)[1]["response"].pop("deferred"), [ANSWERS_OF_THE_DEMO]),
        (lambda c: snippet_of(c, DEMO)[0]["response"].update(deferred=True), [ANSWERS_OF_THE_DEMO]),
        # A line that changes the request before them: Caddy finds a host's errors by the name the request carries.
        (
            before_the_lines({"handle": [{"handler": "headers", "request": {"set": {"Host": ["issuer.internal"]}}}]}),
            [ANSWERS_OF_THE_ISSUER],
        ),
        (
            before_the_lines({"handle": [{"handler": "headers", "request": {"delete": ["Accept-Encoding"]}}]}, DEMO),
            [ANSWERS_OF_THE_DEMO],
        ),
        (
            lambda c: errors_in(c, DEMO).insert(
                0, {"handle": [{"handler": "headers", "request": {"set": {"Host": ["demo.internal"]}}}]}
            ),
            [ERRORS_OF_THE_DEMO],
        ),
        # The two lines not passed by every request, or not before all else.
        (lambda c: routes_of(c, ISSUER)[0].update(match=[{"path": ["/pid/*"]}]), [ANSWERS_OF_THE_ISSUER]),
        (lambda c: routes_of(c, ISSUER)[0].update(match=[{"method": ["GET"]}]), [ANSWERS_OF_THE_ISSUER]),
        (lambda c: routes_of(c, ISSUER)[0].update(group="group9"), [ANSWERS_OF_THE_ISSUER]),
        (before_the_lines({"handle": [respond(200)]}), [ANSWERS_OF_THE_ISSUER]),
        (before_the_lines({"match": [{"path": ["/early"]}], "handle": [respond(200)]}), [ANSWERS_OF_THE_ISSUER]),
        (before_the_lines(handle(["/early"], "group1", respond(200)), DEMO), [ANSWERS_OF_THE_DEMO]),
        (
            before_the_lines({"handle": [{"handler": "vars", "root": "/srv"}], "terminal": True}),
            [ANSWERS_OF_THE_ISSUER],
        ),
        (before_the_lines({"handle": [{"handler": "rewrite", "uri": "/elsewhere"}]}), [ANSWERS_OF_THE_ISSUER]),
        (lambda c: server_of(c)["routes"][ISSUER]["handle"].insert(0, respond(200)), [ANSWERS_OF_THE_ISSUER]),
        (lambda c: server_of(c)["routes"][DEMO].update(handle=[]), [ANSWERS_OF_THE_DEMO]),
        (lambda c: server_of(c)["routes"].pop(DEMO), [ANSWERS_OF_THE_DEMO]),
        (
            lambda c: server_of(c)["routes"].insert(
                0, {"match": [{"host": [HOSTS["issuer"]]}], "handle": [{"handler": "vars", "root": "/srv"}]}
            ),
            [ANSWERS_OF_THE_ISSUER],
        ),
        # A site block for more or for less than one of the two hosts.
        (lambda c: server_of(c)["routes"].append(site("www." + HOSTS["demo"])), [NOT_THE_TWO]),
        (
            lambda c: server_of(c)["routes"][ISSUER]["match"][0].update(path=["/crl/*"]),
            [NOT_THE_TWO, ANSWERS_OF_THE_ISSUER],
        ),
        (lambda c: server_of(c)["routes"][DEMO].pop("match"), [NOT_THE_TWO, ANSWERS_OF_THE_DEMO]),
        (
            lambda c: server_of(c)["routes"][DEMO]["match"].append({"host": [HOSTS["issuer"]]}),
            [NOT_THE_TWO, ANSWERS_OF_THE_DEMO],
        ),
        (lambda c: server_of(c)["routes"][DEMO]["match"][0].update(host=[]), [NOT_THE_TWO, ANSWERS_OF_THE_DEMO]),
        # The errors of a host.
        (lambda c: server_of(c).pop("errors"), [ERRORS_OF_THE_DEMO, ERRORS_OF_THE_ISSUER]),
        (lambda c: server_of(c)["errors"]["routes"].pop(ISSUER), [ERRORS_OF_THE_ISSUER]),
        (
            lambda c: errors_in(c, DEMO)[0].update(match=status_is(502, 503, 504)),
            [ERRORS_OF_THE_DEMO, "match[0].expression, for which this tool has no rule"],
        ),
        (
            lambda c: errors_in(c, DEMO).insert(0, {"match": status_is(404), "handle": [respond(404)]}),
            [ERRORS_OF_THE_DEMO, "match[0].expression, for which this tool has no rule"],
        ),
        (lambda c: errors_in(c, ISSUER)[0]["handle"][0]["routes"][0]["handle"].pop(0), [ERRORS_OF_THE_ISSUER]),
        (
            lambda c: errors_in(c, DEMO).append({"handle": [{"handler": "encode"}]}),
            ["errors.routes[1].handle[0].routes[1].handle[0] (the handler encode), for which this tool has no rule"],
        ),
        (
            lambda c: server_of(c)["errors"]["routes"].append(errors_of("www." + HOSTS["demo"])),
            ["a site block that is not for the two hosts alone, among the errors"],
        ),
    ],
)
def test_each_way_the_reading_departs_from_what_is_known_is_said(change: Callable[[Any], Any], whys: list[str]) -> None:
    found = departing(change)
    assert len(found) == len(whys), found
    for why in whys:
        assert any(why in reason for reason in found), found


@pytest.mark.parametrize(
    "change",
    [
        # What cannot answer and touches neither header may come before the two lines.
        before_the_lines({"handle": [{"handler": "vars", "root": "/srv/public"}]}),
        before_the_lines({"match": [{"path": ["/crl/*"]}], "handle": [{"handler": "vars", "root": "/srv/public"}]}),
        before_the_lines({"handle": [{"handler": "headers", "response": {"set": {"Cache-Control": ["no-store"]}}}]}),
        # A line that changes the request, once the two lines are passed: an error raised from there on has them.
        lambda c: routes_of(c, ISSUER).insert(
            1, {"handle": [{"handler": "headers", "request": {"set": {"Host": ["issuer.internal"]}}}]}
        ),
        lambda c: server_of(c)["routes"][ISSUER]["handle"].insert(0, {"handler": "vars", "root": "/srv/{host}"}),
        # A block that passes the two lines itself, for the requests that enter it.
        before_the_lines({"match": [{"path": ["/early"]}], "handle": [*lines(), respond(200)], "terminal": True}),
        # The two lines the other way round, and written in another case.
        lambda c: snippet_of(c, DEMO).reverse(),
        # A header added or removed beside the two, in the snippet's own lines, by a name that is neither of them.
        lambda c: snippet_of(c, DEMO)[0]["response"].update(add={"Cache-Control": ["no-store"]}),
        lambda c: [
            snippet_of(c, host)[1]["response"].update(delete=["Server", "X-Powered-*"], add={"Vary": ["Origin"]})
            for host in (ISSUER, DEMO)
        ],
        # One more header set beside the two, in one of the two lines or in both, for one host or for both.
        lambda c: snippet_of(c, DEMO)[1]["response"]["set"].update({"Cache-Control": ["no-store"]}),
        lambda c: [
            line["response"]["set"].update({"Referrer-Policy": ["no-referrer"], "a-b": ["1", "2"]})
            for host in (ISSUER, DEMO)
            for line in snippet_of(c, host)
        ],
        lambda c: snippet_of(c, DEMO)[0]["response"].update(set={name.lower(): value for name, value in SET.items()}),
        # One block for both hosts.
        lambda c: (
            server_of(c)["routes"].pop(DEMO),
            server_of(c)["routes"][ISSUER]["match"][0].update(host=list(HOSTS.values())),
        ),
        # A log that goes nowhere, whatever it would hold, and another one that leaves the two loggers out as well.
        lambda c: c["logging"]["logs"].update(nowhere={"writer": {"output": "discard"}, "level": "DEBUG"}),
        lambda c: c["logging"]["logs"].update(more={"exclude": [*sorted(TRY.LEFT_OUT), "tls"], "level": "WARN"}),
        lambda c: c["logging"]["logs"]["default"].update(writer={"output": "stdout"}, encoder={"format": "console"}),
        # Other headers, more routes, another service, other times.
        a_header({"set": {"Cache-Control": ["max-age=3600"]}, "delete": ["Server"], "deferred": True}),
        a_header({"set": copy.deepcopy(SET)}),
        lambda c: routes_of(c, ISSUER).insert(1, handle(["/verifier/*"], "group9", proxy("cunho-verifier:8000"))),
        lambda c: routes_of(c, DEMO).insert(1, {"match": [{"header": {"X-Debug": ["1"]}}], "handle": [respond(200)]}),
        lambda c: server_of(c).update(read_timeout=120000000000, protocols=["h1"]),
        # A site in front of Caddy that is believed about a visitor's address, as docs/DEMO.md has it.
        lambda c: server_of(c).update(
            trusted_proxies={"source": "static", "ranges": ["192.0.2.10/32"]},
            client_ip_headers=["X-Forwarded-For"],
            trusted_proxies_strict=1,
        ),
    ],
)
def test_what_changes_nothing_of_the_two_things_is_still_known_to_hold(change: Callable[[Any], Any]) -> None:
    assert departing(change) == []


def test_whether_routes_begin_with_the_two_lines_is_answered_yes_or_no() -> None:
    assert TRY.begins([{"handle": lines()}]) is True
    for routes in ([], None, [{"handle": [respond(200)]}], [{"handle": lines(), "match": [{"path": ["/x"]}]}]):
        assert TRY.begins(routes) is False


@pytest.mark.parametrize(
    ("log", "taken"),
    [
        ({}, True),
        ({"exclude": ["http.log.error"]}, False),
        ({"exclude": ["http.log"]}, False),  # a name that stands above it
        ({"exclude": ["http"]}, False),
        ({"exclude": ["http.log.err"]}, True),  # a name that only begins the same
        ({"exclude": ["http.log.error.more"]}, True),  # a name that stands below it
        ({"exclude": ["tls", "*"]}, False),  # every module's logger
        ({"include": ["tls", "admin"]}, False),  # a log that includes some takes no other
        ({"include": ["http"]}, True),
        ({"include": ["http.log.error"]}, True),
        ({"include": ["http"], "exclude": ["http.log"]}, False),  # the longer name decides
        ({"include": ["http.log.error"], "exclude": ["http"]}, True),
        ({"include": ["http.log"], "exclude": ["http.log"]}, False),
        ({"exclude": ["."]}, True),  # a dot alone stands for nothing: Caddy takes the logger all the same
        ({"exclude": [""]}, True),
        ({"include": ["*"]}, False),  # and a star among what is included is a name like any other, which nothing has
    ],
)
def test_a_log_takes_a_logger_by_the_longest_name_that_stands_for_it(log: Any, taken: bool) -> None:
    assert TRY.takes(log, "http.log.error") is taken


def a_proxy(config: Any) -> Any:
    """The handler that passes the demo host's requests on."""
    return routes_of(config, DEMO)[2]["handle"][0]["routes"][0]["handle"][0]


SERVER = "apps.http.servers.srv0"
BLOCK = f"{SERVER}.routes[1].handle[0].routes"  # the routes inside the demo host's site block


@pytest.mark.parametrize(
    ("change", "where"),
    [
        # A matcher that can write what a client sent to the log, and others the tool has no rule for.
        (
            lambda c: routes_of(c, DEMO)[1]["match"][0].update(expression="{query.made} != ''"),
            f"{BLOCK}[1].match[0].expression",
        ),
        (
            lambda c: routes_of(c, DEMO)[1]["match"].append({"not": [{"path_regexp": {"pattern": "^/x"}}]}),
            f"{BLOCK}[1].match[1].not[0].path_regexp",
        ),
        (
            lambda c: routes_of(c, DEMO)[1]["match"][0].update(file={"try_files": ["{path}"]}),
            f"{BLOCK}[1].match[0].file",
        ),
        (
            lambda c: routes_of(c, DEMO)[1]["match"][0].update(remote_ip={"ranges": ["10.0.0.0/8"]}),
            f"{BLOCK}[1].match[0].remote_ip",
        ),
        # A service spoken to in another way, and other things said of passing a request on.
        (
            lambda c: a_proxy(c).update(transport={"protocol": "fastcgi"}),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].transport.protocol "
            "(a way of speaking to a service that is not plain HTTP)",
        ),
        (
            lambda c: a_proxy(c).update(transport={"protocol": "http", "tls": {}}),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].transport.tls",
        ),
        (
            lambda c: a_proxy(c).update(transport={"protocol": "http", "forward_proxy_url": "http://proxy.example"}),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].transport.forward_proxy_url",
        ),
        (
            lambda c: a_proxy(c).update(transport={"protocol": "http", "resolver": {"addresses": ["192.0.2.53"]}}),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].transport.resolver",
        ),
        (
            lambda c: a_proxy(c).update(trusted_proxies=["10.0.0.0/8"]),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].trusted_proxies",
        ),
        (
            lambda c: a_proxy(c)["upstreams"][0].update(max_requests=1),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].upstreams[0].max_requests",
        ),
        (
            lambda c: a_proxy(c).update(load_balancing={"retry_match": [{"method": ["POST"]}]}),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].load_balancing.retry_match",
        ),
        (
            lambda c: a_proxy(c).update(dynamic_upstreams={"source": "a"}, upstreams=[]),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].dynamic_upstreams",
        ),
        # A service's health: a Caddy that keeps count of failures counts the ones the cases ask for.
        (
            lambda c: a_proxy(c).update(health_checks={"active": {"uri": "/ok"}, "passive": {"fail_duration": 30}}),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].health_checks",
        ),
        # A name Caddy keeps what it knows of a request under, given another kind of value: its proxy then fails.
        (
            lambda c: routes_of(c, DEMO).insert(
                1,
                {
                    "match": [{"header": {"X-Forwarded-For": ["*"]}}],
                    "handle": [{"handler": "vars", "trusted_proxy": 1}],
                },
            ),
            f"{BLOCK}[1].handle[0].trusted_proxy",
        ),
        (
            lambda c: routes_of(c, DEMO).insert(1, {"handle": [{"handler": "vars", "client_ip": 7}]}),
            f"{BLOCK}[1].handle[0].client_ip",
        ),
        (
            lambda c: routes_of(c, DEMO).insert(1, {"handle": [{"handler": "vars", "root": ["/srv"]}]}),
            f"{BLOCK}[1].handle[0].root (a value that is no text)",
        ),
        (
            lambda c: routes_of(c, DEMO)[1]["handle"][0]["routes"][2]["handle"][0].update(precompressed={"gzip": {}}),
            f"{BLOCK}[1].handle[0].routes[2].handle[0].precompressed",
        ),
        # A file server that lists a folder, a block with errors of its own, a route with more than a route has.
        (
            lambda c: routes_of(c, DEMO)[1]["handle"][0]["routes"][2]["handle"][0].update(browse={}),
            f"{BLOCK}[1].handle[0].routes[2].handle[0].browse",
        ),
        (lambda c: routes_of(c, DEMO)[1]["handle"][0].update(errors={"routes": []}), f"{BLOCK}[1].handle[0].errors"),
        (lambda c: routes_of(c, DEMO)[1].update(more="than a route has"), f"{BLOCK}[1].more"),
        (
            lambda c: errors_in(c, DEMO).append({"handle": [{"handler": "templates"}]}),
            f"{SERVER}.errors.routes[1].handle[0].routes[1].handle[0] (the handler templates)",
        ),
        # A status that the request fills in, in each place a status stands.
        (
            lambda c: routes_of(c, DEMO).insert(
                1, {"handle": [{"handler": "static_response", "status_code": "{http.request.uri.query.status}"}]}
            ),
            f"{BLOCK}[1].handle[0].status_code (a status that is not a fixed one)",
        ),
        (
            lambda c: routes_of(c, DEMO)[1]["handle"][0]["routes"][2]["handle"][0].update(status_code="{query.s}"),
            f"{BLOCK}[1].handle[0].routes[2].handle[0].status_code (a status that is not a fixed one)",
        ),
        (
            lambda c: a_proxy(c).update(handle_response=[{"status_code": "{http.reverse_proxy.header.X-Status}"}]),
            f"{BLOCK}[2].handle[0].routes[0].handle[0].handle_response[0].status_code "
            "(a status that is not a fixed one)",
        ),
        # The TLS policy, the server, the log, and what stands beside the web server.
        (
            lambda c: server_of(c)["tls_connection_policies"][0].update(insecure_secrets_log="/data/secrets"),
            f"{SERVER}.tls_connection_policies[0].insecure_secrets_log",
        ),
        (
            lambda c: server_of(c)["tls_connection_policies"][1].update(client_authentication={"mode": "require"}),
            f"{SERVER}.tls_connection_policies[1].client_authentication",
        ),
        (
            lambda c: server_of(c).update(listener_wrappers=[{"wrapper": "proxy_protocol"}]),
            f"{SERVER}.listener_wrappers",
        ),
        (lambda c: server_of(c).update(automatic_https={"disable_redirects": True}), f"{SERVER}.automatic_https"),
        (lambda c: c["logging"]["logs"]["default"].update(sampling={"first": 1}), "logging.logs.default.sampling"),
        (lambda c: c["logging"].update(sink={"writer": {"output": "stderr"}}), "logging.sink"),
        (lambda c: c["apps"].update(tls={"automation": {"policies": [{"on_demand": True}]}}), "apps.tls"),
        (lambda c: c["apps"]["http"].update(grace_period=1), "apps.http.grace_period"),
        (lambda c: c.update(storage={"module": "file_system"}), "storage"),
        (lambda c: c.update(xtra={}), "xtra"),
    ],
)
def test_whatever_the_reading_holds_that_the_tool_has_no_rule_for_is_told_by_where_it_stands(
    change: Callable[[Any], Any], where: str
) -> None:
    assert departing(change) == [f"Caddy's reading holds {where}, for which this tool has no rule"]


@pytest.mark.parametrize(
    "change",
    [
        # Matchers that only compare what was asked, and the opposite of one.
        lambda c: routes_of(c, DEMO)[1]["match"][0].update(
            header={"X-Debug": ["1"]}, query={"v": ["2"]}, method=["GET"]
        ),
        lambda c: routes_of(c, DEMO)[1]["match"].append({"not": [{"path": ["/pid/*"]}, {"not": [{"host": ["x"]}]}]}),
        # What may be said of passing a request on, of serving a file, of answering and of rewriting.
        lambda c: a_proxy(c).update(
            headers={
                "request": {"set": {"X-Real-Ip": ["{remote}"]}},
                "response": {"set": {"Cache-Control": ["no-store"]}},
            },
            load_balancing={
                "selection_policy": {"policy": "first"},
                "retries": 2,
                "try_duration": 5,
                "try_interval": 1,
            },
            transport={
                **{"protocol": "http", "dial_timeout": 2000000000, "response_header_timeout": 3000000000},
                **{"read_timeout": 1, "write_timeout": 1, "expect_continue_timeout": 1, "dial_fallback_delay": 1},
            },
            flush_interval=-1,
            rewrite={"method": "GET", "uri": "/check"},
            handle_response=[
                {"match": {"status_code": [2]}, "status_code": 200, "routes": [{"handle": [respond(204)]}]}
            ],
        ),
        lambda c: routes_of(c, DEMO)[1]["handle"][0]["routes"][2]["handle"][0].update(
            root="/srv",
            index_names=["index.html"],
            pass_thru=True,
            canonical_uris=False,
            status_code=200,
        ),
        lambda c: routes_of(c, DEMO).insert(
            1,
            {
                "handle": [
                    {
                        "handler": "static_response",
                        "headers": {"Location": ["/o"]},
                        "status_code": 308,
                        "body": "",
                        "close": True,
                    }
                ]
            },
        ),
        lambda c: routes_of(c, DEMO).insert(
            1, {"handle": [{"handler": "static_response", "abort": True}], "match": [{"path": ["/gone"]}]}
        ),
        lambda c: routes_of(c, DEMO).insert(
            1,
            {
                "handle": [
                    {
                        "handler": "rewrite",
                        "strip_path_prefix": "/static",
                        "strip_path_suffix": ".html",
                        "uri_substring": [],
                        "path_regexp": [],
                        "query": {},
                        "method": "GET",
                    }
                ]
            },
        ),
        lambda c: routes_of(c, DEMO).insert(
            1, {"handle": [{"handler": "vars", "root": "/srv"}], "match": [{"path": ["/files/*"]}]}
        ),
        # Of the server and its TLS policy, and of the log.
        lambda c: server_of(c).update(write_timeout=1, max_header_bytes=4096, keepalive_interval=1, read_timeout=2),
        lambda c: server_of(c)["tls_connection_policies"][0].update(curves=["x25519"], alpn=["h2", "http/1.1"]),
        lambda c: c["logging"]["logs"]["default"].update(exclude=["http"], level="ERROR"),
        lambda c: c["logging"]["logs"]["default"].update(exclude=["http.log", "http.handlers"]),
        lambda c: (
            c["logging"]["logs"]["default"].pop("exclude"),
            c["logging"]["logs"]["default"].update(include=["tls", "admin"]),
        ),
    ],
)
def test_what_the_tool_has_a_rule_for_is_known_to_hold(change: Callable[[Any], Any]) -> None:
    assert departing(change) == []


def test_a_status_is_a_fixed_one_that_an_answer_can_have() -> None:
    for fixed in (100, 200, 404, 999, "308"):
        assert list(TRY.a_status(fixed, "there")) == []
    made_up = ("{http.request.uri.query.status}", "{query.status}")
    for other in (*made_up, 99, 1000, 0, -200, 2.5, 200.0, "40", "0404", "404 ", " 404", "", None, True, [404]):
        assert list(TRY.a_status(other, "there")) == ["there (a status that is not a fixed one)"], other


def test_the_rules_are_for_these_parts_of_a_reading_and_for_no_others() -> None:
    """What the tool lets pass is a list, kept short on purpose: a part added to it is a part vouched for."""
    assert TRY.MATCHED_BY == ("host", "path", "method", "header", "query")
    assert TRY.HARMLESS == {"vars"}
    assert {
        *("image", "restart", "cap_drop", "cap_add", "security_opt", "read_only", "ports", "environment", "volumes"),
        *("networks", "logging", "depends_on"),  # what the stack's caddy service has
        *("mem_limit", "mem_reservation", "cpus", "pids_limit", "labels", "container_name", "stop_grace_period"),
    } == TRY.KNOWN, "a key of the caddy service added to these is a key vouched for"
    assert {kind: sorted(keys) for kind, keys in TRY.HANDLERS.items()} == {
        "subroute": ["routes"],
        "headers": ["request", "response"],
        "static_response": ["abort", "body", "close", "headers", "status_code"],
        "rewrite": ["method", "path_regexp", "query", "strip_path_prefix", "strip_path_suffix", "uri", "uri_substring"],
        "vars": ["root"],
        "file_server": ["canonical_uris", "hide", "index_names", "pass_thru", "root", "status_code"],
        "reverse_proxy": [
            *("flush_interval", "handle_response", "headers", "load_balancing", "rewrite", "transport", "upstreams"),
        ],
    }
    proxy_rules = TRY.HANDLERS["reverse_proxy"]
    assert sorted(TRY.HANDLERS["headers"]["response"]) == ["add", "deferred", "delete", "replace", "require", "set"]
    assert sorted(proxy_rules["upstreams"][0]) == ["dial"] and sorted(proxy_rules["headers"]) == ["request", "response"]
    assert sorted(proxy_rules["load_balancing"]) == ["retries", "selection_policy", "try_duration", "try_interval"]
    assert sorted(proxy_rules["handle_response"][0]) == ["match", "routes", "status_code"]
    assert sorted(proxy_rules["transport"]) == [
        *("dial_fallback_delay", "dial_timeout", "expect_continue_timeout", "protocol", "read_timeout"),
        *("response_header_timeout", "write_timeout"),
    ]
    assert proxy_rules["transport"]["protocol"] is TRY.plain_http and TRY.HANDLERS["vars"]["root"] is TRY.a_text
    assert list(TRY.plain_http("http", "x")) == [] and list(TRY.a_text("/srv", "x")) == []
    assert list(TRY.plain_http("fastcgi", "x")) == ["x (a way of speaking to a service that is not plain HTTP)"]
    assert list(TRY.plain_http(None, "x")) and list(TRY.a_text(None, "x")) == ["x (a value that is no text)"]
    statuses = (TRY.HANDLERS["static_response"], TRY.HANDLERS["file_server"], proxy_rules["handle_response"][0])
    assert all(rules["status_code"] is TRY.a_status for rules in statuses), "a status is looked at wherever one stands"
    assert sorted(TRY.READING) == ["admin", "apps", "logging"]
    assert sorted(TRY.READING["logging"]["logs"]["*"]) == ["encoder", "exclude", "include", "level", "writer"]
    assert list(TRY.READING["apps"]) == ["http"] and list(TRY.READING["apps"]["http"]) == ["servers"]
    server = TRY.READING["apps"]["http"]["servers"]["*"]
    assert sorted(server) == [
        *("client_ip_headers", "errors", "idle_timeout", "keepalive_interval", "listen", "logs", "max_header_bytes"),
        *("protocols", "read_header_timeout", "read_timeout", "routes", "tls_connection_policies", "trusted_proxies"),
        *("trusted_proxies_strict", "write_timeout"),
    ]
    assert sorted(server["tls_connection_policies"][0]) == [
        *("alpn", "cipher_suites", "curves", "match", "protocol_max", "protocol_min"),
    ]
    assert sorted(server["trusted_proxies"]) == ["ranges", "source"] and list(server["errors"]) == ["routes"]


@pytest.mark.parametrize(
    "response", [{"delete": ["Strict-Transport-Security"]}, {"set": {"X-Content-Type-Options": ["other"]}}]
)
def test_what_passing_a_request_on_does_to_the_two_headers_of_a_services_answer_is_another_line(response: Any) -> None:
    def changed_answer(config: Any) -> None:
        a_proxy(config).update(headers={"response": response})

    assert departing(changed_answer) == [ANOTHER_LINE]


def test_the_routes_a_proxy_has_for_a_services_answers_are_read_like_the_rest() -> None:
    config = reading()
    inner = [
        {"match": [{"path": ["/in-an-answer"]}], "handle": [proxy("after:8000")]},
        {"handle": [{"handler": "headers", "response": {"delete": ["X-Content-Type-Options"]}}]},
    ]
    a_proxy(config)["handle_response"] = [{"match": {"status_code": [5]}, "routes": inner}, {"status_code": 204}]
    assert TRY.unknown(config, HOSTS) == [ANOTHER_LINE]
    assert ("after", 8000) in TRY.upstreams(config)
    assert ("demo", "GET", "/in-an-answer") in [(c.host, c.method, c.path) for c in TRY.named(config, HOSTS)]
    # And so are those of the second kind of answer it has routes for, and of the third.
    a_proxy(config)["handle_response"] = [{"status_code": 204}, {"routes": []}, {"routes": inner}]
    assert TRY.unknown(config, HOSTS) == [ANOTHER_LINE]
    assert ("after", 8000) in TRY.upstreams(config)
    assert ("demo", "GET", "/in-an-answer") in [(c.host, c.method, c.path) for c in TRY.named(config, HOSTS)]


def test_every_service_of_a_proxy_is_looked_at_and_not_the_first_alone() -> None:
    config = reading()
    a_proxy(config)["upstreams"] = [{"dial": "demo:8000"}, {"dial": "demo-b:8000"}, {"dial": "demo-c:8001"}]
    assert {("demo", 8000), ("demo-b", 8000), ("demo-c", 8001)} <= set(TRY.upstreams(config))
    a_proxy(config)["upstreams"] = [{"dial": "demo:8000"}, {"dial": "unix//run/demo.sock"}]
    with pytest.raises(TRY.CannotTry, match="passes requests on to unix//run/demo.sock, where this tool puts no"):
        TRY.upstreams(config)


def test_the_names_of_another_run_are_not_the_two_hosts() -> None:
    other = {"issuer": "issuer-ffffffff.localhost", "demo": "demo-ffffffff.localhost"}
    found = TRY.unknown(reading(), other)
    assert NOT_THE_TWO in found and ANSWERS_OF_THE_ISSUER in found and ERRORS_OF_THE_DEMO in found


def test_a_reading_with_nothing_in_it_is_not_known_to_hold() -> None:
    found = TRY.unknown({}, HOSTS)
    assert set(found) >= {ANSWERS_OF_THE_ISSUER, ANSWERS_OF_THE_DEMO, ERRORS_OF_THE_ISSUER, ERRORS_OF_THE_DEMO}
    assert NOT_LEFT_OUT in found and any("API is not off" in reason for reason in found)
    assert TRY.access_log({}) is False and TRY.upstreams({}) == [] and TRY.named({}, HOSTS) == []


def test_an_access_log_is_on_when_a_server_has_a_part_for_its_logs() -> None:
    config = reading()
    server_of(config)["logs"] = {"logger_names": {HOSTS["issuer"]: ["log0"]}}
    assert TRY.access_log(config) is True
    for alone in ({"should_log_credentials": True}, {"trace": True}, {}):  # log_credentials or trace by itself
        server_of(config)["logs"] = alone
        assert TRY.access_log(config) is True


@pytest.mark.parametrize(
    "dial",
    ["unix//run/demo.sock", "127.0.0.1:8000", "localhost:8000", "{http.request.host}:8000", "demo", "[::1]:8000"]
    + ["demo:0", "demo:65536", "demo:http", "", "srv+http://demo.internal", "Demo:8000", "-demo:8000"]
    + ["_demo:8000", "demo_:8000", "de mo:8000", "de/mo:8000"],
)
def test_a_service_that_no_stand_in_can_be_put_at_cannot_be_tried(dial: str) -> None:
    config = reading()
    routes_of(config, DEMO)[2]["handle"][0]["routes"][0]["handle"][0]["upstreams"] = [{"dial": dial}] if dial else [{}]
    named = dial or "a service it does not name by a name and a port"
    with pytest.raises(TRY.CannotTry) as refused:
        TRY.upstreams(config)
    assert str(refused.value) == f"the Caddyfile passes requests on to {named}, where this tool puts no stand-in"


def test_every_service_the_caddyfile_passes_on_to_gets_a_stand_in() -> None:
    config = reading()
    routes_of(config, ISSUER).insert(1, handle(["/verifier/*"], "group9", proxy("verifier.internal:8443")))
    routes_of(config, ISSUER).insert(1, handle(["/pid/again"], "group9", proxy("cunho-pid:8000")))
    routes_of(config, ISSUER).insert(1, handle(["/low", "/high"], "group9", proxy("low:1"), proxy("high:65535")))
    routes_of(config, ISSUER).insert(1, handle(["/wallet/*"], "group9", proxy("cunho_wallet-2.internal:8000")))
    errors_in(config, DEMO).append({"handle": [proxy("apology:8080")]})  # where a host's errors are passed on to
    assert TRY.upstreams(config) == [
        ("apology", 8080),
        ("cunho-course", 8000),
        ("cunho-pid", 8000),
        ("cunho_wallet-2.internal", 8000),
        ("demo", 8000),
        ("high", 65535),
        ("low", 1),
        ("verifier.internal", 8443),
    ]


@pytest.mark.parametrize(
    ("more", "which"),
    [
        ({"dynamic_upstreams": {"source": "a", "name": "demo.example", "port": "8000"}}, "dynamic_upstreams"),
        ({"transport": {"protocol": "fastcgi", "capture_stderr": True}}, "transport"),
        ({"transport": {"protocol": "http", "forward_proxy_url": "http://proxy.example:3128"}}, "transport"),
        ({"transport": {"protocol": "http"}, "dynamic_upstreams": {"source": "a"}}, "dynamic_upstreams"),
    ],
)
def test_a_service_looked_up_or_spoken_to_as_the_stand_in_does_not_speak_cannot_be_tried(more: Any, which: str) -> None:
    # What is asked of Caddy would go where no stand-in is, and could leave the run.
    for into in (a_proxy, lambda config: errors_in(config, DEMO).append({"handle": [proxy("apology:8080")]})):
        config = reading()
        (into(config) or errors_in(config, DEMO)[-1]["handle"][0]).update(more)
        with pytest.raises(TRY.CannotTry) as refused:
            TRY.upstreams(config)
        assert str(refused.value) == (
            f"the Caddyfile passes requests on in a way this tool has no stand-in for ({which})"
        )


def test_a_service_spoken_to_in_plain_http_with_times_of_its_own_gets_a_stand_in() -> None:
    config = reading()
    a_proxy(config).update(transport={"protocol": "http", "dial_timeout": 2000000000, "read_timeout": 3000000000})
    assert ("demo", 8000) in TRY.upstreams(config) and TRY.unknown(config, HOSTS) == []


def test_how_long_caddy_tries_a_service_that_is_away_is_read_off_its_reading() -> None:
    config = reading()
    assert TRY.tries(config) == 0 and TRY.tries({}) == 0
    a_proxy(config).update(load_balancing={"try_duration": 5000000000, "try_interval": 250000000})
    assert TRY.tries(config) == 5
    errors_in(config, DEMO).append({"handle": [{**proxy("apology:8080"), "load_balancing": {"try_duration": 30e9}}]})
    assert TRY.tries(config) == 30, "the longest of them, wherever it stands"
    a_proxy(config)["load_balancing"]["try_duration"] = "30s"
    with pytest.raises(ValueError):
        TRY.tries(config)


def test_a_proxy_that_names_no_service_at_all_gets_no_stand_in() -> None:
    config = reading()
    routes_of(config, DEMO)[2]["handle"][0]["routes"][0]["handle"] = [{"handler": "reverse_proxy"}]
    assert TRY.upstreams(config) == [("cunho-course", 8000), ("cunho-pid", 8000)]


def test_every_path_caddy_reads_out_of_the_caddyfile_is_asked() -> None:
    cases = TRY.named(reading(), HOSTS)
    assert [(c.host, c.method, c.path) for c in cases] == [
        ("demo", "GET", "/vct/course-certificate/1"),
        ("issuer", "GET", "/.well-known/oauth-authorization-server/course"),
        ("issuer", "GET", "/.well-known/oauth-authorization-server/pid"),
        ("issuer", "GET", "/.well-known/openid-credential-issuer/course"),
        ("issuer", "GET", "/.well-known/openid-credential-issuer/pid"),
        ("issuer", "GET", "/course"),
        ("issuer", "GET", "/course/admin"),
        ("issuer", "GET", "/course/admin/tried"),
        ("issuer", "GET", "/course/tried"),
        ("issuer", "GET", "/crl/iaca.crl"),
        ("issuer", "GET", "/pid"),
        ("issuer", "GET", "/pid/admin"),
        ("issuer", "GET", "/pid/admin/tried"),
        ("issuer", "GET", "/pid/tried"),
    ]
    assert {c.status for c in cases} == {0}, "any status: the two headers are what is looked for"
    assert {(c.why, c.stand_in, c.leave, c.body, c.allow) for c in cases} == {
        ("a path the Caddyfile names", "ok", None, None, None)
    }
    assert TRY.faults(cases[0], answer(418)) == ([], []) and TRY.faults(cases[0], answer(418, ()))[0] != []


def test_paths_are_read_out_of_a_reading_without_error_blocks_too() -> None:
    config = reading()
    server_of(config).pop("errors")
    assert TRY.named(config, HOSTS) == TRY.named(reading(), HOSTS)


def test_a_matcher_with_a_word_of_the_readings_own_for_a_name_is_read_as_a_matcher() -> None:
    # A query or a header may be named match, handler, routes or handle: they are names, not parts of the reading.
    config = reading()
    odd = {
        "query": {"match": ["*"], "handler": ["x"], "routes": ["y"]},
        "header": {"Handle": ["z"], "Upstreams": ["u"]},
    }
    routes_of(config, DEMO).insert(1, {"match": [{"path": ["/odd"], **odd}], "handle": [respond(200)]})
    assert TRY.unknown(config, HOSTS) == []
    assert TRY.upstreams(config) == TRY.upstreams(reading())
    assert [c.path for c in TRY.named(config, HOSTS) if c.host == "demo"] == ["/odd", "/vct/course-certificate/1"]


def test_a_path_is_asked_for_as_it_can_be_and_left_out_when_it_cannot() -> None:
    config = reading()
    inner = {"handler": "subroute", "routes": [{"match": [{"path": ["/deeper/*"]}], "handle": [respond(200)]}]}
    routes_of(config, DEMO)[1:1] = [
        {"match": [{"path": ["*.css", "/a/*/b", "/A%20b"], "method": ["GET", "POST"]}], "handle": [respond(200)]},
        {"match": [{"path": ["/hook"], "method": ["PUT"]}, {"path": ["/other"]}], "handle": [inner]},
        {"match": [{"path": ["/{http.request.host}/*", "/with space", "/with\ttab", "/q?a=b", "/frag#ment"]}]},
        {"match": [{"path": ["/odd"], "method": ["a method", "LOWER" * 7]}], "handle": [respond(200)]},
        {"match": [{"host": ["www.example.test"], "path": ["/not-of-the-two"]}], "handle": [respond(200)]},
        {"match": [{"path": ["/100%", "/a%zz", "/b%2", "/c%2F"]}], "handle": [respond(200)]},
    ]
    errors_in(config, DEMO).append({"match": [{"path": ["/in-the-errors"]}], "handle": [respond(404)]})
    asked = {(c.method, c.path) for c in TRY.named(config, HOSTS) if c.host == "demo"}
    assert asked == {
        ("GET", "/vct/course-certificate/1"),
        ("GET", "/tried.css"),  # an address begins with a /
        ("POST", "/tried.css"),
        ("GET", "/a/tried/b"),
        ("POST", "/a/tried/b"),
        ("GET", "/A%20b"),
        ("POST", "/A%20b"),
        ("PUT", "/hook"),
        ("GET", "/other"),
        ("PUT", "/deeper/tried"),  # inside a block, with the block's methods
        ("GET", "/deeper/tried"),
        ("GET", "/in-the-errors"),
        ("GET", "/c%2F"),  # a % is asked for only where two hex digits follow it: Go refuses the others unread
    }


@pytest.mark.parametrize(
    ("change", "why"),
    [
        (lambda c: snippet_of(c, DEMO)[0].update(handler="static_response"), ANSWERS_OF_THE_DEMO),
        (lambda c: server_of(c)["routes"][DEMO]["handle"][0].update(handler="rewrite"), ANSWERS_OF_THE_DEMO),
        (before_the_lines({"handle": [{"handler": "subroute"}]}), ANSWERS_OF_THE_ISSUER),
        (before_the_lines({"handle": [{"handler": "subroute", "routes": []}]}), ANSWERS_OF_THE_ISSUER),
    ],
)
def test_what_only_looks_like_the_two_lines_is_not_taken_for_them(change: Callable[[Any], Any], why: str) -> None:
    # A handler of another kind that carries the same words, and a block with nothing in it.
    found = departing(change)
    assert why in found and all(reason == why or reason.endswith("for which this tool has no rule") for reason in found)


def test_a_route_that_does_nothing_and_one_line_of_the_two_may_come_before_both() -> None:
    assert departing(before_the_lines({"match": [{"path": ["/nothing"]}]})) == []
    assert departing(before_the_lines({"handle": []})) == []
    assert departing(before_the_lines({"handle": lines()[:1]})) == []
    assert departing(before_the_lines({"handle": lines()[1:]})) == []


def test_only_what_passes_requests_on_names_a_service() -> None:
    config = reading()
    routes_of(config, ISSUER).insert(1, {"handle": [{"handler": "vars", "upstreams": [{"dial": "no-service:1"}]}]})
    assert TRY.upstreams(config) == TRY.upstreams(reading())


# judging an answer -----------------------------------------------------------------------------------------------


def test_an_answer_is_read_from_what_came_back() -> None:
    raw = b"HTTP/1.1 404 Not Found\r\nServer: Caddy\r\nX-One: a\r\nx-one: b\r\nContent-Length: 4\r\n\r\ngone"
    got = TRY.parse(raw)
    assert (got.status, got.body) == (404, b"gone")
    assert got.values("X-One") == ["a", "b"] and got.values("server") == ["Caddy"] and got.values("absent") == []
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n"
    assert TRY.parse(chunked).body == b"abcde"
    early = TRY.parse(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nX-Final: yes\r\n\r\nbody")
    assert (early.status, early.values("x-final"), early.body) == (200, ["yes"], b"body")
    assert TRY.parse(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n").status == 101
    for interim in (b"100 Continue", b"102 Processing", b"103 Early Hints"):
        assert TRY.parse(b"HTTP/1.1 " + interim + b"\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n").status == 204
    for final in (b"101 Switching Protocols", b"104 Unknown", b"0 Nothing"):  # what follows them is their body
        status = int(final.split()[0])
        got = TRY.parse(b"HTTP/1.1 " + final + b"\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n")
        assert got is None if status == 0 else got.status == status
    for broken in (b"", b"HTTP/1.1 200 OK\r\nServer: Caddy\r\n", b"not HTTP at all\r\n\r\n"):
        assert TRY.parse(broken) is None
    # An interim answer with nothing after it is the answer that came, and a body is a body whatever it begins with.
    assert TRY.parse(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n").status == 103
    in_a_body = TRY.parse(b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 500 only said in a body\r\n\r\n")
    assert (in_a_body.status, in_a_body.body) == (200, b"HTTP/1.1 500 only said in a body\r\n\r\n")
    assert TRY.parse(b"HTTP/1.1 200 OK\r\na line with no colon\r\nX: y\r\n\r\n").headers == (("X", "y"),)
    assert TRY.parse(b"HTTP/1.1 404 Not Found: gone\r\nX: y\r\n\r\n").headers == (("X", "y"),)
    # Only a body that is said to come in chunks is put together from them.
    as_it_is = TRY.parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
    assert as_it_is.body == b"3\r\nabc\r\n0\r\n\r\n"
    both = TRY.parse(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: Chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    )
    assert both.body == b"abc"


def test_an_answer_in_chunks_is_read_up_to_its_last_chunk_or_to_where_it_broke_off() -> None:
    assert TRY.dechunked(b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n") == b"abcde"
    assert TRY.dechunked(b"10\r\n0123456789abcdef\r\n0\r\n\r\n") == b"0123456789abcdef", "a length is in sixteens"
    assert TRY.dechunked(b"A\r\n0123456789\r\n0\r\nTrailer: after the last chunk\r\n\r\n") == b"0123456789"
    assert TRY.dechunked(b"3\r\nabc\r\n") == b"abc", "broken off between two chunks"
    assert TRY.dechunked(b"3\r\nabc\r\n5\r\nde") == b"abcde", "broken off inside a chunk"
    assert TRY.dechunked(b"3\r\nabc\r\nnot a length\r\nde\r\n") == b"abc"
    assert TRY.dechunked(b"") == b"" and TRY.dechunked(b"0\r\n\r\n") == b""


def test_the_right_answer_with_the_two_headers_once_each_has_no_fault() -> None:
    none: tuple[list[str], list[str]] = ([], [])
    assert TRY.faults(case(200), answer(200)) == none
    assert TRY.faults(case(405, allow="GET, HEAD"), answer(405, (*BOTH, ("Allow", "GET, HEAD")))) == none
    assert TRY.faults(case(200, body=b"as sent"), answer(200, body=b"as sent")) == none
    lower = (("strict-transport-security", "max-age=31536000"), ("x-content-type-options", "nosniff"))
    assert TRY.faults(case(200), answer(200, lower)) == none, "a header's name is the same in any case"
    for status in TRY.AWAY:
        assert TRY.faults(case(TRY.AWAY), answer(status)) == none, "any of the answers for a service that is away"
    assert TRY.faults(case(0), answer(418)) == none, "any status, where none is expected"
    # No answer is wrong only where one was expected: a path the Caddyfile closes the connection for has none.
    assert TRY.faults(case(0), TRY.NOTHING) == none
    for nothing in (None, TRY.NOTHING, answer(200, ())):
        assert TRY.faults(case(0, leave="waiting"), nothing) == none, "nothing was waited for"
    # A client that leaves once the head is there has an answer, and it is judged like any other.
    assert TRY.faults(case(200, leave="reading"), answer(200)) == none
    bare, other = TRY.faults(case(200, leave="reading"), answer(502, ()))
    assert len(bare) == 2 and other == ["answered 502, not 200"]


@pytest.mark.parametrize(
    ("expected", "got", "fault"),
    [
        (case(200), answer(200, BOTH[:1]), "x-content-type-options 0 times"),
        (case(200), answer(200, BOTH[1:]), "strict-transport-security 0 times"),
        (case(0), answer(200, BOTH[1:]), "strict-transport-security 0 times"),
        (case(200), answer(200, (*BOTH, BOTH[0])), "strict-transport-security 2 times"),
        (case(200), answer(200, (*BOTH, ("x-content-type-options", "other"))), "x-content-type-options 2 times"),
        (
            case(200),
            answer(200, (("Strict-Transport-Security", "max-age=1"), BOTH[1])),
            "strict-transport-security says max-age=1",
        ),
        (case(200), answer(200, (BOTH[0], ("X-Content-Type-Options", "other"))), "x-content-type-options says other"),
    ],
)
def test_each_way_an_answer_lacks_the_two_headers_is_said(expected: Any, got: Any, fault: str) -> None:
    assert TRY.faults(expected, got) == ([fault], [])


@pytest.mark.parametrize(
    ("expected", "got", "fault"),
    [
        (case(200), None, "an answer that cannot be read"),
        (case(0), None, "an answer that cannot be read"),
        (case(200), TRY.NOTHING, "no answer: the connection was closed"),
        (case(TRY.AWAY), TRY.NOTHING, "no answer: the connection was closed"),
        (case(200), answer(502), "answered 502, not 200"),
        (case(TRY.AWAY), answer(500), "answered 500, not 502 or 503 or 504"),
        (case(405, allow="GET, HEAD"), answer(405), "Allow says nothing"),
        (case(405, allow="GET, HEAD"), answer(405, (*BOTH, ("Allow", "GET"))), "Allow says GET"),
        (
            case(200, body=b"as sent"),
            answer(200, body=b"as sent, and more"),
            "a body of 17 bytes that is not the one expected",
        ),
        (case(200, body=b""), answer(200, body=b"x"), "a body of 1 bytes that is not the one expected"),
    ],
)
def test_an_answer_that_is_not_the_one_a_case_expects_is_another_matter(expected: Any, got: Any, fault: str) -> None:
    # Whether the two headers are there is one thing. Whether the stack still answers this case as it did is another.
    assert TRY.faults(expected, got) == ([], [fault])


def test_an_answer_wrong_in_several_ways_has_each_said_of_its_kind() -> None:
    bare, other = TRY.faults(case(200, allow="GET", body=b"x"), answer(500, ()))
    assert bare == ["strict-transport-security 0 times", "x-content-type-options 0 times"]
    assert other == ["answered 500, not 200", "Allow says nothing", "a body of 0 bytes that is not the one expected"]


def test_an_answer_and_a_case_stay_as_they_were_made() -> None:
    with pytest.raises(AttributeError):
        TRY.NOTHING.status = 200
    with pytest.raises(AttributeError):
        case().status = 0


# judging Caddy's log ---------------------------------------------------------------------------------------------


def test_what_was_written_is_what_was_not_there_before_in_either_stream() -> None:
    before = (["out 1"], ["err 1", "err 2"])
    assert TRY.written(before, (["out 1"], ["err 1", "err 2"])) == []
    assert TRY.written(before, (["out 1", "out 2"], ["err 1", "err 2", "err 3"])) == ["out 2", "err 3"]
    assert TRY.written(([], []), (["out 1"], [])) == ["out 1"]
    # A line that only repeats an earlier one is a line written.
    assert TRY.written(before, (["out 1"], ["err 1", "err 2", "err 2"])) == ["err 2"]


@pytest.mark.parametrize("after", [(["out 1"], ["err 1"]), ([], ["err 1", "err 2"]), (["out 1"], ["err 2", "err 1"])])
def test_a_log_that_no_longer_begins_as_it_did_is_no_log_to_judge_by(after: tuple[list[str], list[str]]) -> None:
    with pytest.raises(TRY.CannotTry, match="no longer holds what it held"):
        TRY.written((["out 1"], ["err 1", "err 2"]), after)


# what the run asks, and what it puts behind Caddy --------------------------------------------------------------


def test_the_cases_are_those_the_review_tried() -> None:
    asked, away = TRY.Case, (502, 503, 504)
    again = ("the same, asked for by its head", "the same, asked for with another method")
    assert TRY.alone(b"the metadata") == [
        asked("issuer", "GET", "/crl/iaca.crl", 200, "a file Caddy serves", body=TRY.CRL),
        asked("issuer", "HEAD", "/crl/iaca.crl", 200, again[0]),
        asked("issuer", "POST", "/crl/iaca.crl", 405, again[1], allow="GET, HEAD"),
        asked("demo", "GET", "/vct/course-certificate/1", 200, "a file Caddy serves", body=b"the metadata"),
        asked("demo", "HEAD", "/vct/course-certificate/1", 200, again[0]),
        asked("demo", "POST", "/vct/course-certificate/1", 405, again[1], allow="GET, HEAD"),
        asked("issuer", "GET", "/no-such-thing", 404, "a path no rule knows"),
        asked("issuer", "GET", "/pid/admin/offers", 404, "the operator API, which stays inside"),
        asked("issuer", "GET", "/pid/status/1", away, "a service that is away"),
        asked("issuer", "GET", "/course/status/1", away, "a service that is away"),
        asked("demo", "GET", "/", away, "a service that is away"),
        asked("issuer", "A" * 33, "/no-such-thing", 405, "a method name too long to be one"),
        asked("demo", "A" * 33, "/", 405, "a method name too long to be one"),
    ]
    # Behind Caddy, each of the three services is asked for an answer of its own, to a GET and to a POST, for a
    # 404 and for an error of its own. Which of them the stand-in gives, a header of the request says.
    behind = TRY.behind()
    said = (b"the service answered", b"the service has no such thing", b"the service failed")
    assert behind[:12] == [
        made
        for host, path in (("issuer", "/pid/tried"), ("issuer", "/course/tried"), ("demo", "/tried"))
        for made in (
            asked(host, "GET", path, 200, "a service's own answer", body=said[0]),
            asked(host, "POST", path, 200, "the same, to a POST", body=said[0]),
            asked(host, "GET", path, 404, "a service's own 404", body=said[1], stand_in="missing"),
            asked(host, "GET", path, 500, "a service's own error", body=said[2], stand_in="boom"),
        )
    ]
    one = ("issuer", "GET", "/pid/tried")
    assert behind[12:] == [
        asked(*one, 200, "a service that switches protocols unasked", body=b"", stand_in="switch"),
        asked(*one, 200, "the same, with no word of what it switches to", body=b"", stand_in="bare"),
        asked(*one, 200, "an answer the service cuts short", stand_in="cut"),
        asked(*one, 200, "an answer the client leaves half way", stand_in="stream", leave="reading"),
        asked(*one, 0, "a client that leaves while the service is silent", stand_in="silent", leave="waiting"),
    ]


def test_what_the_cases_are_made_with() -> None:
    assert len(TRY.CRL) > 20 and TRY.CRL not in TRY.SAID.values(), "a body that no other answer has"
    assert TRY.LONG == "A" * 33, "letters alone, and one more of them than Caddy takes for a method"
    assert 1 <= TRY.LINGER <= 5, "long enough for Caddy to have passed the request on, and short enough for a run"
    assert inspect.signature(TRY.ask).parameters["wait"].default == TRY.PATIENCE == 15, "and not for long"


needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="the stand-in is a shell script, and there is no sh")


def stand_in(kind: str | None, target: str = "/pid/tried") -> Any:
    """What the stand-in answers to a request as Caddy passes one on, asked for one of its answers or for none."""
    cue = f"X-Stand-In: {kind}\r\n" if kind is not None else ""
    request = f"GET {target} HTTP/1.1\r\nHost: cunho-pid:8000\r\nUser-Agent: Go\r\n{cue}Accept-Encoding: gzip\r\n\r\n"
    script = ["sh", "-c", TRY.HANDLER]
    return TRY.parse(subprocess.run(script, input=request.encode(), capture_output=True, timeout=10, check=True).stdout)


@needs_sh
@pytest.mark.parametrize(("kind", "status"), [("ok", 200), ("missing", 404), ("boom", 500)])
def test_the_stand_in_answers_with_its_own_copies_of_the_two_headers(kind: str, status: int) -> None:
    got = stand_in(kind)
    assert (got.status, got.body) == (status, TRY.SAID[kind])
    # Its own, with other values: Caddy has to replace them, which is what the cases then look for.
    assert got.values("strict-transport-security") == ["max-age=1"]
    assert got.values("x-content-type-options") == ["other"]
    assert got.values("content-length") == [str(len(TRY.SAID[kind]))]


@needs_sh
def test_the_stand_in_switches_protocols_unasked_and_cuts_an_answer_short() -> None:
    switched = stand_in("switch")
    assert switched.status == 101 and switched.values("upgrade") == ["websocket"]
    bare = stand_in("bare")  # at this one Caddy's proxy writes an error, with the client's address when it may
    assert bare.status == 101 and bare.headers == () and bare.body == b""
    cut = stand_in("cut")
    assert cut.status == 200 and cut.values("content-length") == ["1000000"] and len(cut.body) < 100


def stand_in_left_running(kind: str) -> subprocess.Popen[bytes]:
    """The stand-in asked for an answer that does not end by itself, in a group of its own to be stopped with."""
    request = f"GET /pid/tried HTTP/1.1\r\nHost: cunho-pid:8000\r\nX-Stand-In: {kind}\r\n\r\n".encode()
    script = ["sh", "-c", TRY.HANDLER]
    process = subprocess.Popen(script, stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True)
    assert process.stdin is not None
    process.stdin.write(request)
    process.stdin.close()
    return process


def stopped_for_good(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(10)


@needs_sh
def test_the_stand_in_goes_on_sending_an_answer_that_has_no_end() -> None:
    process = stand_in_left_running("stream")
    in_any_case = threading.Timer(20, process.kill)
    in_any_case.start()
    got = b""
    try:
        assert process.stdout is not None
        while len(got) < 200_000 and (chunk := os.read(process.stdout.fileno(), 65536)):
            got += chunk
    finally:
        in_any_case.cancel()
        stopped_for_good(process)
    head, _, body = got.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200 OK\r\n") and b"content-length" not in head.lower()
    assert len(body) > 2 * 65536, "it goes on, piece after piece, for a client to leave half way"


@needs_sh
def test_the_stand_in_asked_to_be_silent_says_nothing_and_stays() -> None:
    process = stand_in_left_running("silent")
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(1)
    finally:
        stopped_for_good(process)
    assert process.stdout is not None and process.stdout.read() == b""


@needs_sh
@pytest.mark.parametrize("target", ["/pid/missing", "/boom", "/pid/switch", "/course/cut", "/stream", "/silent/x"])
def test_no_path_asks_the_stand_in_for_one_of_its_odd_answers(target: str) -> None:
    # A Caddyfile may name any path: what the stand-in answers is said by the header alone, and without it, as
    # when the run looks whether the stand-in is there, it gives its plain answer.
    for kind in ("ok", None, "no-such-answer"):
        got = stand_in(kind, target)
        assert (got.status, got.body) == (200, TRY.SAID["ok"]), (kind, target)


def test_the_files_go_into_the_container_by_their_paths() -> None:
    files = {"etc/caddy/Caddyfile": b"{\n}\n", "/srv/public/iaca.crl": TRY.CRL, "/x/x": b""}
    with tarfile.open(fileobj=io.BytesIO(TRY.archive(files))) as tar:
        assert tar.getnames() == ["etc/caddy/Caddyfile", "srv/public/iaca.crl", "x/x"]
        held = tar.extractfile("srv/public/iaca.crl")
        assert held is not None and held.read() == TRY.CRL
        assert all(member.mode == 0o644 for member in tar.getmembers())


# asking, with Caddy played by a server on this machine -----------------------------------------------------------


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A key and a certificate that nobody vouches for, as Caddy's own are for the names of a run."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "played, for the tests of try_caddy.py")])
    now = datetime.datetime.now(datetime.UTC)
    signed = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    own = key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path = tmp_path_factory.mktemp("played") / "key-and-certificate.pem"
    path.write_bytes(own + signed.public_bytes(pem))
    return path


class Played:
    """A server on this machine that stands for Caddy. It takes one connection after another over TLS, keeps what
    was asked and under which name, and answers with what `say` writes."""

    def __init__(self, certificate: Path, say: Callable[[ssl.SSLSocket], Any]) -> None:
        self.say = say
        self.asked: list[bytes] = []
        self.names: list[str | None] = []
        self.spoken: list[str | None] = []
        self.left: list[bytes] = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate)
        self.context.set_alpn_protocols(["h2", "http/1.1"])
        self.context.sni_callback = lambda connection, name, context: self.names.append(name)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.05)  # serve() looks every now and then whether it is to stop
        self.port: int = self.listener.getsockname()[1]
        self.done, self.closing = threading.Event(), threading.Event()
        self.serving = threading.Thread(target=self.serve, daemon=True)
        self.serving.start()

    def serve(self) -> None:
        while not self.closing.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with self.context.wrap_socket(connection, server_side=True) as tls:
                    tls.settimeout(10)
                    self.spoken.append(tls.selected_alpn_protocol())
                    head = b""
                    while b"\r\n\r\n" not in head and (chunk := tls.recv(4096)):
                        head += chunk
                    self.asked.append(head)
                    self.say(tls)
            except OSError:
                pass
            finally:
                self.done.set()

    def __enter__(self) -> Played:
        return self

    def close(self) -> None:
        """The listener is closed once nothing waits at it any more. Closed under a thread that waited there, it
        has been seen not to come back, on a Mac that had much else to do."""
        self.closing.set()
        self.serving.join(15)
        self.listener.close()

    def __exit__(self, *left: Any) -> None:
        self.close()


def a_page(tls: ssl.SSLSocket) -> None:
    tls.sendall(
        b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\n"
        b"Content-Length: 6\r\n\r\na page"
    )


def test_a_request_carries_the_hosts_name_and_what_the_stand_in_is_to_answer(certificate: Path) -> None:
    asked = TRY.Case("issuer", "POST", "/pid/tried", 200, "a case", stand_in="boom")
    with Played(certificate, a_page) as caddy:
        got = TRY.ask(caddy.port, HOSTS["issuer"], asked)
    assert got == answer(200, (*BOTH, ("Content-Length", "6")), b"a page")
    assert caddy.asked == [
        b"POST /pid/tried HTTP/1.1\r\nHost: issuer-0a1b2c3d.localhost\r\nX-Stand-In: boom\r\nConnection: close\r\n\r\n"
    ]
    assert caddy.names == [HOSTS["issuer"]], "the name goes into the TLS hello, where Caddy picks the certificate"
    assert caddy.spoken == ["http/1.1"], "HTTP/1.1 is all that is offered"
    assert TRY.faults(asked, got) == ([], [])


def test_a_connection_closed_with_nothing_sent_is_no_answer_and_not_an_unreadable_one(certificate: Path) -> None:
    with Played(certificate, lambda tls: None) as caddy:
        assert TRY.ask(caddy.port, HOSTS["demo"], case()) is TRY.NOTHING
    with Played(certificate, lambda tls: tls.sendall(b"something that is not HTTP\r\n\r\n")) as caddy:
        assert TRY.ask(caddy.port, HOSTS["demo"], case()) is None
    with Played(certificate, lambda tls: tls.sendall(b"HTTP/1.1 200 OK\r\nServer: Cad")) as caddy:
        assert TRY.ask(caddy.port, HOSTS["demo"], case()) is None, "a head broken off is no answer"


class Broken:
    """A connection that is reset once what it holds has been read."""

    def __init__(self, *came: bytes) -> None:
        self.came = list(came)

    def __enter__(self) -> Broken:
        return self

    def __exit__(self, *left: Any) -> None:
        return None

    def sendall(self, data: bytes) -> None:
        return None

    def settimeout(self, wait: float) -> None:
        return None

    def recv(self, most: int) -> bytes:
        if not self.came:
            raise ConnectionResetError("reset by the other end")
        return self.came.pop(0)


def test_an_answer_that_is_broken_off_is_judged_by_what_had_come(monkeypatch: pytest.MonkeyPatch) -> None:
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n"
    monkeypatch.setattr(TRY, "connected", lambda port, name, wait: Broken(head, b"the st"))
    assert TRY.ask(1, HOSTS["issuer"], case()) == answer(200, (("Content-Length", "9"),), b"the st")
    monkeypatch.setattr(TRY, "connected", lambda port, name, wait: Broken())
    assert TRY.ask(1, HOSTS["issuer"], case()) is TRY.NOTHING, "and by nothing, when nothing had come"


def test_an_answer_that_does_not_come_in_time_is_not_waited_for(certificate: Path) -> None:
    release = threading.Event()
    with Played(certificate, lambda tls: release.wait(10)) as caddy:
        with pytest.raises(TRY.CannotTry) as refused:
            TRY.ask(caddy.port, HOSTS["issuer"], case(), wait=0.4)
        release.set()
    assert "Caddy gave no answer to GET /pid/tried of the issuer host within" in str(refused.value)


def test_an_answer_whose_head_came_is_judged_by_it_however_long_the_rest_takes(certificate: Path) -> None:
    release = threading.Event()

    def head_and_no_more(tls: ssl.SSLSocket) -> None:
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nonly the start")
        release.wait(10)

    with Played(certificate, head_and_no_more) as caddy:
        got = TRY.ask(caddy.port, HOSTS["issuer"], case(), wait=1.0)
        release.set()
    assert got is not None and (got.status, got.body) == (200, b"only the start")


def test_no_more_of_an_answer_is_read_than_the_limit(certificate: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def without_end(tls: ssl.SSLSocket) -> None:
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n")
        while True:
            tls.sendall(bytes(65536))

    monkeypatch.setattr(TRY, "LIMIT", 200_000)
    with Played(certificate, without_end) as caddy:
        got = TRY.ask(caddy.port, HOSTS["issuer"], case(), wait=30)
    assert got is not None and got.status == 200 and 100_000 < len(got.body) < 400_000


def test_a_client_that_leaves_half_way_goes_once_the_head_is_there(certificate: Path) -> None:
    def without_end(tls: ssl.SSLSocket) -> None:
        tls.sendall(b"HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n")
        while True:
            tls.sendall(bytes(4096))

    with Played(certificate, without_end) as caddy:
        got = TRY.ask(caddy.port, HOSTS["issuer"], case(leave="reading"), wait=30)
        assert caddy.done.wait(10), "the server saw the client go"
    assert got is not None and got.status == 200 and len(got.body) < TRY.LIMIT


def test_a_client_that_leaves_half_way_stays_for_the_whole_head(certificate: Path) -> None:
    def head_in_two_and_no_end(tls: ssl.SSLSocket) -> None:
        tls.sendall(b"HTTP/1.1 200 OK\r\nX-Content-Ty")
        time.sleep(0.2)
        tls.sendall(b"pe-Options: nosniff\r\n\r\n")
        while True:
            tls.sendall(bytes(4096))

    with Played(certificate, head_in_two_and_no_end) as caddy:
        got = TRY.ask(caddy.port, HOSTS["issuer"], case(leave="reading"), wait=30)
    assert got is not None and got.status == 200 and got.values("x-content-type-options") == ["nosniff"]


def test_a_client_that_leaves_while_it_waits_reads_nothing(certificate: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stayed: list[float] = []

    def waits_for_the_client_to_go(tls: ssl.SSLSocket) -> None:
        since = time.monotonic()
        caddy.left.append(tls.recv(4096))  # nothing more comes: the client has gone
        stayed.append(time.monotonic() - since)

    monkeypatch.setattr(TRY, "LINGER", 0.3)
    with Played(certificate, waits_for_the_client_to_go) as caddy:
        got = TRY.ask(caddy.port, HOSTS["issuer"], case(0, stand_in="silent", leave="waiting"))
        assert caddy.done.wait(10)
    assert got is TRY.NOTHING and caddy.left == [b""]
    assert b"X-Stand-In: silent\r\n" in caddy.asked[0]
    assert stayed[0] > 0.2, "it stays a while before it goes: Caddy has to have passed the request on by then"


def test_the_time_to_wait_is_for_the_whole_answer_and_not_for_each_piece(certificate: Path) -> None:
    release = threading.Event()

    def late_and_never_whole(tls: ssl.SSLSocket) -> None:
        time.sleep(0.8)
        tls.sendall(b"HTTP/1.1 2")
        release.wait(10)

    with Played(certificate, late_and_never_whole) as caddy:
        since = time.monotonic()
        with pytest.raises(TRY.CannotTry, match="Caddy gave no answer to GET /pid/tried of the issuer host"):
            TRY.ask(caddy.port, HOSTS["issuer"], case(), wait=1.0)
        assert 0.9 <= time.monotonic() - since < 1.5
        release.set()


def test_once_the_time_is_up_nothing_more_is_read(certificate: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Late:
        """A clock on which the time is up as soon as the request has been sent."""

        looked = 0

        def monotonic(self) -> float:
            self.looked += 1
            return 0.0 if self.looked == 1 else 15.0  # to the instant

    monkeypatch.setattr(TRY, "time", Late())
    with Played(certificate, a_page) as caddy:
        with pytest.raises(TRY.CannotTry, match="Caddy gave no answer to GET /pid/tried of the issuer host within 15"):
            TRY.ask(caddy.port, HOSTS["issuer"], case())


def test_once_the_limit_is_reached_nothing_more_is_waited_for(
    certificate: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()
    whole = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nthe first of it"

    def all_at_once_and_then_nothing(tls: ssl.SSLSocket) -> None:
        tls.sendall(whole)
        release.wait(10)

    monkeypatch.setattr(TRY, "LIMIT", len(whole))
    with Played(certificate, all_at_once_and_then_nothing) as caddy:
        since = time.monotonic()
        got = TRY.ask(caddy.port, HOSTS["issuer"], case(), wait=5.0)
        assert time.monotonic() - since < 2.5
        release.set()
    assert got is not None and got.body == b"the first of it"


def test_an_answer_that_comes_in_pieces_is_read_to_its_end(certificate: Path) -> None:
    def in_pieces(tls: ssl.SSLSocket) -> None:
        for piece in (b"HTTP/1.1 200 OK\r\nContent-Le", b"ngth: 11\r\n\r\nthree ", b"par", b"ts"):
            tls.sendall(piece)
            time.sleep(0.05)

    with Played(certificate, in_pieces) as caddy:
        got = TRY.ask(caddy.port, HOSTS["issuer"], case())
    assert got is not None and (got.status, got.body) == (200, b"three parts")


def test_no_more_of_an_answer_is_read_than_about_a_megabyte(certificate: Path) -> None:
    def without_end(tls: ssl.SSLSocket) -> None:
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n")
        while True:
            tls.sendall(bytes(65536))

    with Played(certificate, without_end) as caddy:
        got = TRY.ask(caddy.port, HOSTS["issuer"], case(), wait=30)
    assert got is not None and got.status == 200 and (1 << 20) - 200 <= len(got.body) < (1 << 20) + (1 << 17)


def test_every_connection_goes_to_the_loopback_and_waits_no_longer_than_it_says(
    certificate: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    went: list[tuple[Any, Any]] = []
    connect = socket.create_connection

    def noting(address: Any, timeout: Any = None) -> socket.socket:
        went.append((address, timeout))
        return connect(address, timeout=timeout)

    monkeypatch.setattr(TRY.socket, "create_connection", noting)
    with Played(certificate, a_page) as caddy:
        TRY.greeted(caddy.port, HOSTS["demo"])
        TRY.ask(caddy.port, HOSTS["demo"], case(), wait=7.0)
        TRY.poke(caddy.port)
    assert went == [(("127.0.0.1", caddy.port), 5), (("127.0.0.1", caddy.port), 7.0), (("127.0.0.1", caddy.port), 5)]


def test_a_caddy_that_takes_no_connection_cannot_be_asked(certificate: Path) -> None:
    with pytest.raises(
        TRY.CannotTry, match="Caddy took no connection for GET /pid/tried of the issuer host .*: it may have stopped"
    ):
        TRY.ask(unused_port(), HOSTS["issuer"], case())
    with socket.create_server(("127.0.0.1", 0)) as no_tls:  # it takes the connection and never speaks TLS
        threading.Thread(target=lambda: no_tls.accept()[0].close(), daemon=True).start()
        with pytest.raises(TRY.CannotTry, match="Caddy took no connection for GET /pid/tried of the issuer host"):
            TRY.ask(no_tls.getsockname()[1], HOSTS["issuer"], case())


def unused_port() -> int:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port: int = listener.getsockname()[1]
    return port


def test_caddy_is_there_once_it_completes_a_handshake_under_a_name(certificate: Path) -> None:
    with Played(certificate, lambda tls: None) as caddy:
        assert TRY.greeted(caddy.port, HOSTS["demo"]) is True
        assert caddy.done.wait(10) and caddy.names == [HOSTS["demo"]]
    assert TRY.greeted(unused_port(), HOSTS["demo"]) is False, "nothing listens there"
    with socket.create_server(("127.0.0.1", 0)) as no_tls:  # it takes the connection and never speaks TLS
        threading.Thread(target=lambda: no_tls.accept()[0].close(), daemon=True).start()
        assert TRY.greeted(no_tls.getsockname()[1], HOSTS["demo"]) is False


def test_the_client_that_speaks_no_tls_sends_plain_http_and_minds_no_answer() -> None:
    got: list[bytes] = []

    def take_one(listener: socket.socket) -> None:
        connection, _ = listener.accept()
        with connection:
            got.append(connection.recv(4096))

    with socket.create_server(("127.0.0.1", 0)) as listener:
        thread = threading.Thread(target=take_one, args=(listener,), daemon=True)
        thread.start()
        TRY.poke(listener.getsockname()[1])
        thread.join(10)
    assert got == [b"GET / HTTP/1.1\r\nHost: nobody\r\n\r\n"]
    TRY.poke(unused_port())  # nothing listens there, and nothing is made of it


def test_the_client_that_speaks_no_tls_stays_for_what_comes_back() -> None:
    def refuse(listener: socket.socket) -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")

    with socket.create_server(("127.0.0.1", 0)) as listener:
        thread = threading.Thread(target=refuse, args=(listener,), daemon=True)
        thread.start()
        assert TRY.poke(listener.getsockname()[1]) == b"HTTP/1.0 400 Bad Request\r\n\r\n"
        thread.join(10)
    assert TRY.poke(unused_port()) == b""


# the commands given to Docker --------------------------------------------------------------------------------------


class Command:
    """A docker command, played: what docker() starts, feeds and waits for, and what a test has it do meanwhile."""

    started: list[Command] = []
    ends: Any = (0, b"out", b"err")  # how it ends, or what is raised while it is waited for
    as_it_starts: Callable[[], None] | None = None

    def __init__(self, command: list[str], **how: Any) -> None:
        self.command, self.how, self.killed = command, how, False
        self.waited: list[tuple[bytes | None, float | None]] = []
        masked: Callable[[Any, Any], Any] = getattr(signal, "pthread_sigmask", lambda how, which: set())
        self.held_back = masked(signal.SIG_BLOCK, [])  # the signals not taken while it is started
        if Command.as_it_starts is not None:
            Command.as_it_starts()
        Command.started.append(self)
        self.returncode = 0

    def communicate(self, data: bytes | None = None, timeout: float | None = None) -> tuple[bytes, bytes]:
        self.waited.append((data, timeout))
        if self.killed:
            return b"", b""
        if isinstance(Command.ends, BaseException):
            raise Command.ends
        self.returncode, out, err = Command.ends
        return out, err

    def kill(self) -> None:
        self.killed = True


@pytest.fixture
def commands(monkeypatch: pytest.MonkeyPatch) -> type[Command]:
    monkeypatch.setattr(Command, "started", [])
    monkeypatch.setattr(Command, "ends", (0, b"out", b"err"))
    monkeypatch.setattr(Command, "as_it_starts", None)
    monkeypatch.setattr(TRY.subprocess, "Popen", Command)
    return Command


def test_one_docker_command_is_run_in_a_session_of_its_own(commands: type[Command]) -> None:
    done = TRY.docker("cp", "-", "caddy:/", data=b"a tar")
    assert (done.args, done.returncode, done.stdout, done.stderr) == (("cp", "-", "caddy:/"), 0, b"out", b"err")
    ran = commands.started[-1]
    assert ran.command == ["docker", "cp", "-", "caddy:/"] and ran.waited == [(b"a tar", 120)]
    piped = subprocess.PIPE
    # Out of reach of a Ctrl-C at the terminal: this tool takes that, and ends the command itself.
    assert ran.how == {"stdin": piped, "stdout": piped, "stderr": piped, "start_new_session": True}
    TRY.docker("rm", "-f", "caddy", wait=7)
    ran = commands.started[-1]
    assert ran.waited == [(None, 7)] and ran.how["stdin"] == subprocess.DEVNULL, "it reads nothing of this tool's"
    assert ran.how["start_new_session"] is True and not ran.killed


def test_what_stands_in_the_way_of_a_docker_command_is_said(commands: type[Command]) -> None:
    commands.ends = (1, b"", b"Error response from daemon: no such \xff container\n")
    done = TRY.docker("rm", "-f", "caddy", check=False)
    assert done.returncode == 1 and done.stderr.startswith(b"Error"), "asked not to mind, it gives the result as it is"
    with pytest.raises(TRY.CannotTry, match="docker rm -f: Error response from daemon: no such � container$"):
        TRY.docker("rm", "-f", "caddy")
    long = "it began " + "x" * 500 + " and here it ended \n"
    commands.ends = (1, b"", long.encode())
    with pytest.raises(TRY.CannotTry) as refused:
        TRY.docker("start", "caddy")
    assert str(refused.value) == "docker start caddy: " + long[-400:].strip(), "the last 400 characters of it"
    assert len(str(refused.value)) == len("docker start caddy: ") + 398
    commands.ends = subprocess.TimeoutExpired("docker", 540)
    with pytest.raises(TRY.CannotTry, match="docker pull did not come back within 540 seconds"):
        TRY.docker("pull", IMAGE, wait=540)
    ran = commands.started[-1]
    assert ran.killed and ran.waited == [(None, 540), (None, None)], "it is ended, and what is left of it taken"
    commands.ends = BrokenPipeError(32, "Broken pipe")  # whatever goes wrong while it is waited for
    with pytest.raises(TRY.CannotTry, match="docker logs could not be run: .*Broken pipe"):
        TRY.docker("logs", "caddy")
    assert commands.started[-1].killed


@pytest.mark.parametrize(
    ("fails", "told"),
    [
        (
            FileNotFoundError(2, "No such file or directory", "docker"),
            "Docker is needed, and there is no docker command here",
        ),
        (BlockingIOError(35, "Resource temporarily unavailable"), "docker version could not be run: .*unavailable"),
        (PermissionError(13, "Permission denied", "docker"), "docker version could not be run: .*Permission denied"),
    ],
)
def test_a_docker_command_that_cannot_be_started_is_no_fault_of_the_tool(
    commands: type[Command], fails: OSError, told: str
) -> None:
    def cannot() -> None:
        raise fails

    commands.as_it_starts = cannot
    with pytest.raises(TRY.CannotTry, match=told):
        TRY.docker("version", check=False)
    assert commands.started == []


def test_where_signals_cannot_be_held_back_a_command_is_run_all_the_same(
    commands: type[Command], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(signal, "pthread_sigmask")
    assert TRY.docker("version").stdout == b"out" and commands.started[-1].held_back == set()


@pytest.mark.parametrize("ends", [KeyboardInterrupt(), RuntimeError("anything")])
def test_a_docker_command_is_ended_with_whatever_ends_the_wait_for_it(commands: type[Command], ends: Any) -> None:
    commands.ends = ends
    with pytest.raises(type(ends)):
        TRY.docker("exec", "caddy", "sh")
    ran = commands.started[-1]
    assert ran.killed and ran.waited == [(None, 120), (None, None)]


def test_no_signal_to_end_is_taken_while_a_command_is_being_started(commands: type[Command]) -> None:
    """Taken then, it leaves a command that is neither waited for nor ended: a container made a moment after
    what the run started was removed. It is held back until the command is there, and ends the command with it."""
    signal.signal(signal.SIGTERM, TRY.stopped)
    commands.as_it_starts = lambda: os.kill(os.getpid(), signal.SIGTERM)
    with pytest.raises(KeyboardInterrupt):
        TRY.docker("create", "--name", "caddy", IMAGE)
    ran = commands.started[-1]
    assert set(TRY.STOPS) <= ran.held_back, "all three are held back while it starts"
    assert ran.killed and ran.waited == [(None, None)], "and the one that came is taken once the command is there"
    assert not set(TRY.STOPS) & signal.pthread_sigmask(signal.SIG_BLOCK, []), "afterwards they are taken as before"
    # A command that cannot be started leaves them as they were as well.
    commands.as_it_starts = None
    commands.ends = (0, b"", b"")
    TRY.docker("version")
    assert not set(TRY.STOPS) & signal.pthread_sigmask(signal.SIG_BLOCK, [])


def test_while_what_was_started_is_removed_no_signal_to_end_is_heard() -> None:
    def mine(number: int, frame: Any) -> None:
        return None

    before = {number: signal.signal(number, mine) for number in TRY.STOPS}
    try:
        assert TRY.STOPS == (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        with TRY.undisturbed():
            assert all(signal.getsignal(number) is signal.SIG_IGN for number in TRY.STOPS)
        assert all(signal.getsignal(number) is mine for number in TRY.STOPS)
        with pytest.raises(RuntimeError), TRY.undisturbed():
            raise RuntimeError("whatever goes wrong meanwhile")
        assert all(signal.getsignal(number) is mine for number in TRY.STOPS), "heard again afterwards"
    finally:
        for number, handler in before.items():
            signal.signal(number, handler)


def test_a_signal_this_system_does_not_have_is_not_one_to_end_at(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "try_caddy_under_test", TRY)  # the tool is loaded once more, and put back
    monkeypatch.delattr(signal, "SIGHUP")
    assert tool().STOPS == (signal.SIGINT, signal.SIGTERM)


class Docker:
    """Docker, played. Every command is noted with how it was given, and answered by its first words: with what a
    test put there for them, or with nothing and no error."""

    def __init__(self) -> None:
        self.ran: list[tuple[str, ...]] = []
        self.how: list[dict[str, Any]] = []
        self.clock = Clock()
        self.answers: dict[str, Any] = {
            "port": b"127.0.0.1:49153\n",
            "inspect": b"true\n",
        }

    def __call__(self, *args: str, data: bytes | None = None, check: bool = True, wait: float = 120) -> Any:
        self.ran.append(args)
        heard = signal.getsignal(signal.SIGINT)
        self.how.append({"data": data, "check": check, "wait": wait, "heard": heard})
        words = "_".join(args[:2]) if args[0] in ("network", "image") else args[0]
        if args[0] == "exec":
            words = f"exec_{args[2]}"
        said = self.answers.get(words, b"")
        said = said(args) if callable(said) else said
        code, out, err = said if isinstance(said, tuple) else (0, said, b"")
        if check and code:
            raise TRY.CannotTry(f"docker {' '.join(args[:2])}: {err.decode()}")
        return subprocess.CompletedProcess(args, code, out, err)

    def first_words(self) -> list[str]:
        return [" ".join(args[:2]) if args[0] in ("network", "rm") else args[0] for args in self.ran]


FILES = {"etc/caddy/Caddyfile": b"{\n\tadmin off\n}\n", "srv/public/iaca.crl": b"a CRL"}
REMOVED = ["rm -f", "rm -f", "rm -f", "network rm"]  # the reading's container, Caddy's, the stand-in's, the network


@pytest.fixture
def docker(monkeypatch: pytest.MonkeyPatch) -> Docker:
    played = Docker()
    monkeypatch.setattr(TRY, "docker", played)
    monkeypatch.setattr(TRY, "greeted", lambda port, name: True)
    monkeypatch.setattr(TRY, "time", played.clock)
    return played


def test_a_run_begins_with_a_network_and_nothing_in_it(docker: Docker) -> None:
    with TRY.Rig(IMAGE, FILES) as rig:
        label = ("--label", f"cunho.try-caddy={rig.name}")
        assert docker.ran == [("network", "create", *label, rig.name)], "Caddy is started once its names are held"
        assert rig.started == [f"the network {rig.name}"]
    assert docker.first_words() == ["network create", *REMOVED]


def test_a_run_starts_one_caddy_on_the_loopback_and_removes_what_it_started(docker: Docker) -> None:
    with TRY.Rig(IMAGE, FILES) as rig:
        rig.start()
        assert docker.first_words() == ["network create", "create", "cp", "start", "port"]
        assert rig.port == 49153
        tag = rig.name.removeprefix("try-caddy-")
        assert len(tag) == 8 and rig.hosts == {"issuer": f"issuer-{tag}.localhost", "demo": f"demo-{tag}.localhost"}
        label = ("--label", f"cunho.try-caddy={rig.name}")
        assert docker.ran[0] == ("network", "create", *label, rig.name)
        assert docker.ran[1] == (
            *("create", "--name", f"{rig.name}-caddy", "--network", rig.name),
            *("-p", "127.0.0.1::443"),  # the loopback alone, at a port the machine picks
            *("--log-driver", "json-file"),  # where docker logs reads it, whatever this Docker keeps logs in
            *label,
            *("-e", f"ISSUER_HOST={rig.hosts['issuer']}", "-e", f"DEMO_HOST={rig.hosts['demo']}"),
            IMAGE,  # and nothing of this machine mounted, nothing fetched
        )
        assert docker.ran[2] == ("cp", "-", f"{rig.name}-caddy:/") and docker.how[2]["data"] == TRY.archive(FILES)
        assert docker.ran[3] == ("start", f"{rig.name}-caddy")
        assert docker.ran[4] == ("port", f"{rig.name}-caddy", "443/tcp")
        assert all(how["heard"] is not signal.SIG_IGN for how in docker.how), "a Ctrl-C is heard while it runs"
    assert docker.ran[5:] == [
        ("rm", "-f", "-v", f"{rig.name}-reading"),
        ("rm", "-f", "-v", f"{rig.name}-caddy"),
        ("rm", "-f", "-v", f"{rig.name}-service"),
        ("network", "rm", rig.name),
    ]
    for how in docker.how[5:]:  # deaf to a Ctrl-C, and whatever each of them answers
        assert how["check"] is False and how["heard"] is signal.SIG_IGN


def test_the_names_of_a_run_are_its_own(docker: Docker) -> None:
    one, other = TRY.Rig(IMAGE, FILES), TRY.Rig(IMAGE, FILES)
    assert one.name != other.name and not set(one.hosts.values()) & set(other.hosts.values())
    assert one.proof != other.proof and one.name in one.proof


def test_what_was_started_is_removed_whatever_ends_the_run(docker: Docker) -> None:
    with pytest.raises(KeyboardInterrupt), TRY.Rig(IMAGE, FILES):
        raise KeyboardInterrupt
    assert docker.first_words()[-4:] == REMOVED
    assert all(how["heard"] is signal.SIG_IGN for how in docker.how[-4:]), "deaf to a second signal after a first"

    def gives_way(args: tuple[str, ...]) -> Any:
        raise TRY.CannotTry("docker rm did not come back within 120 seconds")

    # And when Docker itself gives way while it removes: the rest is still removed, and the first error is the one told.
    docker.answers["rm"] = gives_way
    docker.ran.clear()
    with pytest.raises(ValueError, match="the first"), TRY.Rig(IMAGE, FILES):
        raise ValueError("the first")
    assert docker.first_words()[-4:] == REMOVED
    assert all(how["heard"] is signal.SIG_IGN for how in docker.how[-4:])


@pytest.mark.parametrize("ends", [KeyboardInterrupt, ValueError])
def test_stopped_while_it_starts_a_run_removes_what_it_had_started(
    docker: Docker, monkeypatch: pytest.MonkeyPatch, ends: type[BaseException]
) -> None:
    def stopped(port: int, name: str) -> bool:
        raise ends

    monkeypatch.setattr(TRY, "greeted", stopped)  # Caddy is started, and is being waited for
    with pytest.raises(ends), TRY.Rig(IMAGE, FILES) as rig:
        rig.start()
    assert docker.first_words() == ["network create", "create", "cp", "start", "port", *REMOVED]


def test_stopped_while_its_network_is_made_a_run_removes_it(docker: Docker) -> None:
    def stopped(args: tuple[str, ...]) -> Any:
        raise KeyboardInterrupt

    docker.answers["network_create"] = stopped
    with pytest.raises(KeyboardInterrupt):
        TRY.Rig(IMAGE, FILES).__enter__()
    assert docker.first_words() == ["network create", *REMOVED]


def test_what_docker_does_not_remove_is_told_with_how_to_remove_it(
    docker: Docker, capsys: pytest.CaptureFixture[str]
) -> None:
    def gives_way(args: tuple[str, ...]) -> Any:
        raise TRY.CannotTry("docker rm did not come back within 30 seconds")

    never_there = (1, b"", b"Error response from daemon: No such container: x")

    def at_the_end(rig: Any) -> None:
        docker.answers["network_rm"] = (1, b"", b"Error response from daemon: network has active endpoints")
        docker.answers["rm"] = lambda args: gives_way(args) if args[-1].endswith("-caddy") else never_there

    with TRY.Rig(IMAGE, FILES) as rig:
        at_the_end(rig)
    said = capsys.readouterr()
    by_hand = f"docker rm -f -v {rig.name}-caddy; docker network rm {rig.name}"
    assert said.err == f"Docker did not remove all that this run started. By hand: {by_hand}\n" and said.out == ""
    assert [how["wait"] for how in docker.how[-4:]] == [30] * 4, "a removal is not waited for as long as the rest"
    # It is told as well after a run that failed or was stopped, which is when Docker is likeliest to fail too.
    for ends in (KeyboardInterrupt, ValueError):
        with pytest.raises(ends), TRY.Rig(IMAGE, FILES) as rig:
            at_the_end(rig)
            raise ends
        by_hand = f"docker rm -f -v {rig.name}-caddy; docker network rm {rig.name}"
        assert capsys.readouterr().err == f"Docker did not remove all that this run started. By hand: {by_hand}\n"
    # Whatever keeps one thing from being removed, the next is tried all the same, and what stays is told.
    with TRY.Rig(IMAGE, FILES) as rig:

        def breaks(args: tuple[str, ...]) -> Any:
            raise RuntimeError("something nobody foresaw")

        docker.answers["rm"] = breaks
        docker.answers["network_rm"] = b""
    stays = "; ".join(f"docker rm -f -v {rig.name}-{part}" for part in ("reading", "caddy", "service"))
    assert capsys.readouterr().err == f"Docker did not remove all that this run started. By hand: {stays}\n"
    assert docker.first_words()[-4:] == REMOVED
    # Words that only sound like "never there" do not make a thing gone.
    with TRY.Rig(IMAGE, FILES) as rig:
        docker.answers["rm"] = (1, b"", b"Error response from daemon: driver not found: No such device")
        docker.answers["network_rm"] = (1, b"", b"Error response from daemon: plugin not found")
    assert capsys.readouterr().err.count("docker ") == 4
    # What was never there is gone as well, in the words Docker has for a container and for a network.
    with TRY.Rig(IMAGE, FILES):
        docker.answers["rm"] = never_there
        docker.answers["network_rm"] = (1, b"", b"Error response from daemon: network x not found")
    assert capsys.readouterr().err == ""


def test_what_stays_is_told_after_what_was_printed(docker: Docker, monkeypatch: pytest.MonkeyPatch) -> None:
    noted: list[str] = []
    for name in ("stdout", "stderr"):
        monkeypatch.setattr(sys, name, Noting(getattr(sys, name), name, noted))
    with TRY.Rig(IMAGE, FILES):
        print("a line about an answer")
        docker.answers["network_rm"] = (1, b"", b"Error response from daemon: network has active endpoints")
    assert noted.index("stdout flushed") < noted.index("stderr written"), noted


@pytest.mark.parametrize("written", [False, True], ids=["none to print to", "one that cannot be written to"])
def test_what_stays_is_told_whatever_became_of_standard_output(
    docker: Docker, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], written: bool
) -> None:
    class NoRoom:
        """Standard output on a disk that is full: what is printed is taken, and cannot be written out."""

        def write(self, text: str) -> int:
            return len(text)

        def flush(self) -> None:
            raise OSError(28, "No space left on device")

    with monkeypatch.context() as during:
        during.setattr(sys, "stdout", NoRoom() if written else None)
        with TRY.Rig(IMAGE, FILES) as rig:
            docker.answers["network_rm"] = (1, b"", b"Error response from daemon: network has active endpoints")
    by_hand = f"docker network rm {rig.name}"
    assert capsys.readouterr().err == f"Docker did not remove all that this run started. By hand: {by_hand}\n"


def test_what_stays_and_cannot_be_told_to_anyone_ends_a_run_no_otherwise(
    docker: Docker, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Said with an error of its own, it would be that error the run ends in, whatever the run had found."""
    with open(no_reader(), "w", encoding="utf-8") as stream:
        monkeypatch.setattr(sys, "stderr", stream)
        with TRY.Rig(IMAGE, FILES):
            docker.answers["network_rm"] = (1, b"", b"Error response from daemon: network has active endpoints")
        stream.flush()  # and nothing is left that cannot be written


def test_asked_to_keep_it_leaves_what_it_started_and_says_what(
    docker: Docker, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with TRY.Rig(IMAGE, FILES, keep=True) as rig:
        rig.start()
    assert "rm" not in [args[0] for args in docker.ran] and ("network", "rm", rig.name) not in docker.ran
    out = capsys.readouterr().out
    assert out == f"left as it is: the network {rig.name}, the container {rig.name}-caddy\n", "no stand-in was started"
    with TRY.Rig(IMAGE, FILES, keep=True) as rig:
        rig.hold_the_names([("demo", 8000)])
    assert capsys.readouterr().out.endswith(f", the container {rig.name}-service\n")
    assert "rm" not in [args[0] for args in docker.ran]


def test_a_caddy_that_stops_at_once_could_not_do_what_the_caddyfile_says(docker: Docker) -> None:
    docker.answers.update(port=b"", logs=(0, b"", b"Error: loading initial config: listen tcp :443: bind\n"))
    with pytest.raises(TRY.CannotTry) as refused, TRY.Rig(IMAGE, FILES) as rig:
        rig.start()
    assert str(refused.value).startswith("Caddy did not start. It wrote:\nError: loading initial config")
    # What it wrote is told as far as it can be read: bytes that are no text, and a Docker that minds the asking.
    docker.answers["port"] = (1, b"", b"Error: No public port '443/tcp' published")
    docker.answers["logs"] = (1, b"it wrote \xff\xfe and went\n", b"Error: no such container\n")
    with pytest.raises(TRY.CannotTry) as refused, TRY.Rig(IMAGE, FILES) as rig:
        rig.start()
    assert (
        str(refused.value)
        == "Caddy did not start. It wrote:\nit wrote \ufffd\ufffd and went\nError: no such container\n"
    )
    assert docker.first_words()[-4:] == REMOVED, "and what was started is removed"

    def hangs(args: tuple[str, ...]) -> Any:
        raise TRY.CannotTry("docker logs did not come back within 120 seconds")

    docker.answers["logs"] = hangs  # what it wrote cannot be had: that it did not start is said all the same
    with pytest.raises(TRY.CannotTry) as refused, TRY.Rig(IMAGE, FILES) as rig:
        rig.start()
    assert str(refused.value) == (
        "Caddy did not start. It wrote:\n(not to be had: docker logs did not come back within 120 seconds)"
    )


def test_a_caddy_that_stops_or_greets_nobody_cannot_be_tried(docker: Docker, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(TRY, "greeted", lambda port, name: False)
    docker.answers.update(inspect=b"false\n", logs=(0, b"", b"Error: loading initial config\n"))
    did_not_start = "Caddy did not start. It wrote:\nError: loading initial config"
    with pytest.raises(TRY.CannotTry, match=did_not_start), TRY.Rig(IMAGE, FILES) as rig:
        rig.start()
    assert ("inspect", "-f", "{{.State.Running}}", f"{rig.name}-caddy") in docker.ran
    assert docker.first_words()[-4:] == REMOVED
    docker.answers["inspect"] = (1, b"", b"Error: No such object")  # gone altogether
    with pytest.raises(TRY.CannotTry, match=did_not_start), TRY.Rig(IMAGE, FILES) as rig:
        rig.start()
    # One that runs and greets nobody is waited for a minute. Of what it wrote, the last 1500 characters are told.
    long = b"it began " + b"x" * 2000 + b" and here it ended\n"
    docker.answers.update(inspect=b"true\n", logs=(0, b"", long))
    with pytest.raises(TRY.CannotTry) as refused, TRY.Rig(IMAGE, FILES) as rig:
        start = docker.clock.now
        rig.start()
    assert 60 <= docker.clock.now - start < 60.5
    told = "Caddy runs, and completed no TLS handshake within a minute. It wrote:\n"
    assert str(refused.value) == told + long.decode()[-1500:] and len(long) > 1500
    assert docker.first_words()[-4:] == REMOVED


def test_caddy_is_waited_for_until_it_greets_under_both_names(docker: Docker, monkeypatch: pytest.MonkeyPatch) -> None:
    tried: list[tuple[int, str]] = []

    def at_the_third_try(port: int, name: str) -> bool:
        tried.append((port, name))
        return tried.count((port, name)) == 3

    monkeypatch.setattr(TRY, "greeted", at_the_third_try)
    with TRY.Rig(IMAGE, FILES) as rig:
        start = docker.clock.now
        rig.start()
        assert tried == [(49153, rig.hosts["issuer"])] * 3 + [(49153, rig.hosts["demo"])] * 3
        assert 1.2 <= docker.clock.now - start < 1.6, "a moment between two tries, four times, and no longer"


def test_caddys_reading_is_asked_of_a_caddy_that_has_the_file_and_no_network(docker: Docker) -> None:
    docker.answers["run"] = json.dumps(reading()).encode()
    with TRY.Rig(IMAGE, FILES) as rig:
        assert rig.adapted() == reading()
        read = "cat > /etc/caddy/Caddyfile && exec caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile"
        assert docker.ran[-1] == (
            *("run", "--rm", "-i", "--network", "none", "--name", f"{rig.name}-reading"),
            *("--label", f"cunho.try-caddy={rig.name}"),
            *("-e", f"ISSUER_HOST={rig.hosts['issuer']}", "-e", f"DEMO_HOST={rig.hosts['demo']}"),
            *("--entrypoint", "sh", IMAGE, "-c", read),  # it starts no server
        )
        assert docker.how[-1]["data"] == FILES["etc/caddy/Caddyfile"], "the file as it is, where the stack mounts it"
        assert docker.first_words() == ["network create", "run"], "before the Caddy of the run is started"
        for unreadable in (b"", b"not JSON", b"[]", b'"a text"'):
            docker.answers["run"] = unreadable
            with pytest.raises(TRY.CannotTry, match="what Caddy made of the Caddyfile could not be read"):
                rig.adapted()
        # A Caddyfile that Caddy does not take: what it wrote of it is told, as far as a message carries.
        wrote = b"Error: adapting config using caddyfile: unrecognized directive: nope\n"
        docker.answers["run"] = (1, b"", b"x" * 2000 + wrote)
        with pytest.raises(TRY.CannotTry) as refused:
            rig.adapted()
        told = "Caddy does not take the Caddyfile. It wrote:\n"
        assert str(refused.value) == told + ("x" * 2000 + wrote.decode())[-1500:]


def test_caddys_log_is_read_stream_by_stream_and_an_unreadable_one_is_no_log(docker: Docker) -> None:
    with TRY.Rig(IMAGE, FILES) as rig:
        docker.answers["logs"] = (0, b"to stdout\n\n", b"one\n  \ntwo \xff\n")
        assert rig.log() == (["to stdout"], ["one", "two \ufffd"]), "a line is a line whatever bytes it holds"
        assert docker.ran[-1] == ("logs", f"{rig.name}-caddy")
        docker.answers["logs"] = (
            1,
            b"",
            b"Error response from daemon: configured logging driver does not support reading\n",
        )
        with pytest.raises(TRY.CannotTry, match="Caddy's log could not be read: Error response .* does not support"):
            rig.log()


def test_the_log_is_taken_once_it_is_quiet_and_shows_the_line_written_to_it(docker: Docker) -> None:
    with TRY.Rig(IMAGE, FILES) as rig:
        start = "\n".join(AT_THE_START[:3]).encode() + b"\n"
        grown = [start, start + rig.proof.encode() + b"\n", start + rig.proof.encode() + b"\nlate\n"]
        reads: list[bytes] = []

        def growing(args: tuple[str, ...]) -> tuple[int, bytes, bytes]:
            reads.append(grown[min(len(reads), 2)])
            return 0, b"", reads[-1]

        docker.answers["logs"] = growing
        began = docker.clock.now
        assert rig.quiet_log() == ([], [*AT_THE_START[:3], rig.proof, "late"])
        assert len(reads) == 4, "read until two readings in a row are the same"
        assert docker.clock.now - began == 3, "a second between two readings"
        written = [args for args in docker.ran if args[0] == "exec"]
        assert written == [("exec", f"{rig.name}-caddy", "sh", "-c", f'echo "{rig.proof}" > /proc/1/fd/2')]
        assert not set('"$`\\') & set(rig.proof), "it goes between a shell's quotes as it is"


def test_a_log_in_which_the_line_written_to_it_does_not_show_is_no_log(docker: Docker) -> None:
    with TRY.Rig(IMAGE, FILES) as rig:
        docker.answers["logs"] = (0, b"", "\n".join(AT_THE_START).encode())
        with pytest.raises(TRY.CannotTry, match="a line this run wrote to it does not show in it"):
            rig.quiet_log()
        docker.answers["logs"] = (0, rig.proof.encode(), b"")  # in the other stream it is not the line written
        with pytest.raises(TRY.CannotTry, match="a line this run wrote to it does not show in it"):
            rig.quiet_log()
        docker.answers["exec_sh"] = (1, b"", b"sh: can't create /proc/1/fd/2: Permission denied")
        with pytest.raises(TRY.CannotTry, match="docker exec .*: sh: can't create"):
            rig.quiet_log()


def test_a_log_that_never_stops_growing_cannot_be_judged(docker: Docker) -> None:
    with TRY.Rig(IMAGE, FILES) as rig:
        reads: list[int] = []

        def growing(args: tuple[str, ...]) -> tuple[int, bytes, bytes]:
            reads.append(1)
            return 0, b"", (rig.proof + "\n" + "one more\n" * len(reads)).encode()

        docker.answers["logs"] = growing
        start = docker.clock.now
        with pytest.raises(TRY.CannotTry, match="Caddy goes on writing to its log while nothing is asked of it"):
            rig.quiet_log()
        assert len(reads) == 21 and docker.clock.now - start == 20, "it is given twenty seconds to fall quiet"


def test_the_names_are_held_inside_the_run_with_nothing_that_listens(docker: Docker) -> None:
    with TRY.Rig(IMAGE, FILES) as rig:
        rig.hold_the_names([("cunho-pid", 8000), ("cunho-status", 9000), ("demo", 8000)])
        assert docker.ran[-1] == (
            *("run", "-d", "--name", f"{rig.name}-service", "--network", rig.name),
            *("--network-alias", "cunho-pid", "--network-alias", "cunho-status", "--network-alias", "demo"),
            *("--label", f"cunho.try-caddy={rig.name}"),
            *("-e", f"HANDLER={TRY.HANDLER}", "-e", "PORTS=8000 9000"),
            # The Caddy image itself, for the shell it carries: published nowhere, mounted nowhere, and idle.
            *("--entrypoint", "sh", IMAGE, "-c", "tail -f /dev/null"),
        )
        assert rig.started[-1] == f"the container {rig.name}-service"
        assert not [args for args in docker.ran if args[0] == "exec"], "nothing is started in it yet"


def test_the_stand_in_is_started_where_the_names_are_held_at_every_port(
    docker: Docker, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[tuple[int, str, str]] = []
    statuses = iter([502, 503, 504, 200, None, 200])  # away three times, there, unreadable once, there

    def played(port: int, name: str, asked_for: Any, wait: float = 15.0) -> Any:
        asked.append((port, name, asked_for.path))
        status = next(statuses)
        return answer(status) if status else None

    reached: list[str] = []

    def wget(args: tuple[str, ...]) -> bytes:
        reached.append(args[-1])
        return TRY.SAID["ok"] if reached.count(args[-1]) == 2 else b""

    monkeypatch.setattr(TRY, "ask", played)
    docker.answers["exec_wget"] = wget
    with TRY.Rig(IMAGE, FILES) as rig:
        rig.start()
        start = docker.clock.now
        rig.put_a_service_behind([("cunho-pid", 8000), ("cunho-status", 9000), ("demo", 8000)])
        waited = docker.clock.now - start
        listen = 'for port in $PORTS; do nc -lk -p "$port" -e sh /tmp/handler.sh & done; wait'
        assert not [args for args in docker.ran if args[0] == "run"], "no second container: the names stay where held"
        assert next(args for args in docker.ran if args[0] == "exec") == (
            *("exec", "-d", f"{rig.name}-service", "sh", "-c"),
            'printf "%s" "$HANDLER" > /tmp/handler.sh; ' + listen,
        )
        # Caddy's own container is asked whether it reaches the stand-in, at each name and port, until it does.
        wgets = [args for args in docker.ran if args[:3] == ("exec", f"{rig.name}-caddy", "wget")]
        ask_it = ("exec", f"{rig.name}-caddy", "wget", "-q", "-O", "-", "-T", "2")  # its body alone, soon
        assert wgets == [
            (*ask_it, "http://cunho-pid:8000/"),
            (*ask_it, "http://cunho-pid:8000/"),
            (*ask_it, "http://cunho-status:9000/"),
            (*ask_it, "http://cunho-status:9000/"),
            (*ask_it, "http://demo:8000/"),
            (*ask_it, "http://demo:8000/"),
        ]
        # Then Caddy is asked until it passes a request on, for each of the three services.
        issuer, demo = rig.hosts["issuer"], rig.hosts["demo"]
        assert asked == [
            *[(49153, issuer, "/pid/tried")] * 4,  # away three times, then there
            (49153, issuer, "/course/tried"),
            (49153, demo, "/tried"),
        ]
        # Three times the stand-in was not there yet and three times Caddy did not pass on: a moment after each.
        assert 2.4 <= waited < 3.0


def test_a_stand_in_that_is_not_reached_cannot_be_tried_with(docker: Docker) -> None:
    docker.answers.update(exec_wget=(1, b"", b"wget: bad address"), logs=(0, b"", b"nc: bind: Address in use\n"))
    with TRY.Rig(IMAGE, FILES) as rig:
        start = docker.clock.now
        with pytest.raises(TRY.CannotTry) as refused:
            rig.put_a_service_behind([("demo", 8000)])
        assert docker.ran[-1] == ("logs", f"{rig.name}-service")
        assert 30 <= docker.clock.now - start < 30.5, "it is given half a minute"
    assert (
        str(refused.value) == "the stand-in service did not answer at demo:8000. It wrote:\nnc: bind: Address in use\n"
    )


def test_a_caddy_that_has_stopped_is_not_taken_for_a_stand_in_that_does_not_answer(docker: Docker) -> None:
    docker.answers.update(exec_wget=(1, b"", b"Error: container is not running"), inspect=b"false\n")
    docker.answers["logs"] = (0, b"", b"its last words\n")
    with TRY.Rig(IMAGE, FILES) as rig:
        start = docker.clock.now
        with pytest.raises(TRY.CannotTry) as refused:
            rig.put_a_service_behind([("demo", 8000)])
        assert docker.clock.now - start < 1, "it is said at once, not after half a minute"
        assert docker.ran[-1] == ("logs", f"{rig.name}-caddy")
    assert str(refused.value) == "Caddy has stopped. It wrote:\nits last words\n"


def test_a_caddy_that_never_passes_a_request_on_is_judged_by_its_answers(
    docker: Docker, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker.answers["exec_wget"] = TRY.SAID["ok"]
    monkeypatch.setattr(TRY, "ask", lambda port, name, asked, wait=15.0: answer(503))
    with TRY.Rig(IMAGE, FILES) as rig:
        rig.start()
        rig.put_a_service_behind([("demo", 8000)])  # it comes to an end: the cases then say what is wrong


def test_asked_to_keep_it_names_only_what_was_made(docker: Docker, capsys: pytest.CaptureFixture[str]) -> None:
    docker.answers["create"] = (1, b"", b"Error response from daemon: no space left on device")
    with (
        pytest.raises(TRY.CannotTry, match="docker create --name: .*no space left"),
        TRY.Rig(IMAGE, FILES, True) as rig,
    ):
        rig.start()
    assert capsys.readouterr().out == f"left as it is: the network {rig.name}\n", "no container was made"


def test_asked_to_keep_it_says_nothing_when_nothing_was_started(
    docker: Docker, capsys: pytest.CaptureFixture[str]
) -> None:
    docker.answers["network_create"] = (1, b"", b"permission denied while trying to connect to the Docker daemon")
    with pytest.raises(TRY.CannotTry, match="docker network create: permission denied"):
        TRY.Rig(IMAGE, FILES, keep=True).__enter__()
    assert capsys.readouterr().out == ""


# the run, with Caddy played by what follows ---------------------------------------------------------------------


def right(asked: Any) -> Any:
    more = (("Allow", asked.allow),) if asked.allow else ()
    status = asked.status if isinstance(asked.status, int) else asked.status[0]
    return TRY.Answer(status or 200, (*BOTH, *more), asked.body or b"")


class Noting:
    """A stream that keeps, beside what is written to it, when it was written to and when it was flushed."""

    def __init__(self, stream: Any, name: str, noted: list[str]) -> None:
        self.stream, self.name, self.noted = stream, name, noted

    def write(self, text: str) -> int:
        self.noted.append(f"{self.name} written")
        return int(self.stream.write(text))

    def flush(self) -> None:
        self.noted.append(f"{self.name} flushed")
        self.stream.flush()


class Run:
    """One run of the tool with Docker and Caddy played: what Caddy reads, answers and writes is the test's."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        self.monkeypatch, self.capsys = monkeypatch, capsys
        self.config: Any = reading()
        self.ask: Callable[[Any], Any] = right
        self.lines: tuple[str, ...] = ()
        self.line_after: dict[int, str] = {}  # a line Caddy writes once so many things have been asked
        self.asked_before_the_log: int | None = None
        self.asked_before_the_stand_in: int | None = None
        self.held: list[list[tuple[str, int]]] = []
        self.did: list[tuple[str, int]] = []  # what was done to the rig, and how much had been asked by then
        self.before: tuple[list[str], list[str]] = ([], list(AT_THE_START))
        self.files: list[dict[str, bytes]] = []
        self.behind: list[list[tuple[str, int]]] = []
        self.asked: list[Any] = []
        self.poked: list[int] = []
        self.docker = Docker()
        self.clock = Clock()
        self.poked_at = self.read_at = 0.0
        self.entered = self.left = 0
        self.ignored: tuple[int, ...] = ()  # the signals this run is started to ignore
        self.streams: list[str] | None = None  # when asked for: each write to, and flush of, its two streams
        self.nowhere = False  # started with its standard output closed
        self.printed_to: Any = None  # another standard output than the one that is read here
        self.out = self.err = ""

    def __call__(self, *argv: str) -> int:
        run = self

        class PlayedRig:
            port, hosts, name = 49153, HOSTS, "try-caddy-0a1b2c3d"

            def __init__(self, image: str, files: dict[str, bytes], keep: bool = False) -> None:
                assert image == TRY.service(COMPOSE) and keep is ("--keep" in argv)
                run.files.append(files)

            def __enter__(self) -> Any:
                run.entered += 1
                return self

            def __exit__(self, *left: Any) -> None:
                run.left += 1

            def adapted(self) -> Any:
                run.did.append(("Caddy's reading is taken", len(run.asked)))
                taken = [signal.getsignal(number) for number in TRY.STOPS]
                to_be = [signal.SIG_IGN if number in run.ignored else TRY.stopped for number in TRY.STOPS]
                assert taken == to_be, "a signal to end is taken as Ctrl-C is, whichever it is"
                return run.config(self) if callable(run.config) else run.config

            def ask(self, asked: Any) -> Any:
                run.asked.append(asked)
                return run.ask(asked)

            def hold_the_names(self, where: list[tuple[str, int]]) -> None:
                run.did.append(("the names are held", len(run.asked)))
                run.held.append(where)

            def start(self) -> None:
                run.did.append(("Caddy is started", len(run.asked)))

            def put_a_service_behind(self, where: list[tuple[str, int]]) -> None:
                assert run.held[-1:] == [where], "the stand-in is started where the names are held"
                run.did.append(("a service is put behind", len(run.asked)))
                run.asked_before_the_stand_in = len(run.asked)
                run.behind.append(where)

            def so_far(self) -> list[str]:
                return [line for after, line in sorted(run.line_after.items()) if len(run.asked) >= after]

            def quiet_log(self) -> tuple[list[str], list[str]]:
                run.did.append(("the log is read for the first time", len(run.asked)))
                run.asked_before_the_log = len(run.asked)
                return run.before[0], [*run.before[1], *self.so_far()]

            def log(self) -> tuple[list[str], list[str]]:
                run.read_at = run.clock.now
                return run.before[0], [*run.before[1], *self.so_far(), *run.lines]

        self.monkeypatch.setattr(TRY, "Rig", PlayedRig)
        self.monkeypatch.setattr(TRY, "docker", self.docker)
        self.monkeypatch.setattr(TRY, "poke", self.poke)
        self.monkeypatch.setattr(TRY, "time", self.clock)
        self.monkeypatch.setattr(sys, "argv", ["try_caddy.py", *argv])
        for number in self.ignored:
            signal.signal(number, signal.SIG_IGN)
        if self.streams is not None:
            for name in ("stdout", "stderr"):
                self.monkeypatch.setattr(sys, name, Noting(getattr(sys, name), name, self.streams))
        heard = [signal.getsignal(number) for number in TRY.STOPS]
        with self.monkeypatch.context() as during:
            if self.nowhere or self.printed_to is not None:
                during.setattr(sys, "stdout", self.printed_to)
            code = int(TRY.main())
        assert [signal.getsignal(number) for number in TRY.STOPS] == heard, "and afterwards as before"
        assert self.left == self.entered, "what a run started is removed, however the run ended"
        self.out, self.err = self.capsys.readouterr()
        assert "AssertionError" not in self.err, self.err  # what the played rig found wrong is no fault of the tool
        return code

    def poke(self, port: int) -> bytes:
        self.poked.append(port)
        self.poked_at = self.clock.now
        return b""


@pytest.fixture
def a_run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Run:
    return Run(monkeypatch, capsys)


def test_when_everything_holds_it_says_so_and_prints_the_digests(a_run: Run) -> None:
    assert a_run() == 0
    assert a_run.err == ""
    assert "  ??  " not in a_run.out and "  NO " not in a_run.out
    known = "  ok  the two headers' lines first for each host and its errors, and no other line for either of them\n"
    known += "  ok  no access log, and a log that leaves out Caddy's errors and its proxy and can be read here\n"
    known += "  ok  nothing in it that this tool has no rule for\n"
    assert f"what Caddy makes of the file\n{known}nothing behind Caddy\n" in a_run.out
    # A line for each thing asked: how, of which host, what, the status that came, and why it is asked.
    assert re.search(r"\n  ok  GET {8}issuer /crl/iaca\.crl +200  a file Caddy serves\n", a_run.out)
    too_long = r"\n  ok  AAA\.\.\.\(33\) issuer /no-such-thing +405  a method name too long to be one\n"
    assert re.search(too_long, a_run.out)
    assert a_run.docker.ran[0] == ("version",), "Docker is asked whether it is there before anything else"
    assert "Caddy's log: nothing written while it was asked" in a_run.out
    assert "\nIt holds: Caddy reads the file as it must, every answer carries the two headers once each" in a_run.out
    for name, digest in TRY.digests(CADDYFILE, COMPOSE).items():
        assert f'    "{name}": "{digest}",\n' in a_run.out
    assert "which is not deploy/Caddyfile" not in a_run.out
    # Caddy ran on the Caddyfile as it is on disk, with the two files it serves beside it.
    assert a_run.files[0]["etc/caddy/Caddyfile"] == (ROOT / "deploy" / "Caddyfile").read_bytes()
    served_too = ["srv/public/iaca.crl", "srv/type_metadata/course-certificate-1.json"]
    assert sorted(a_run.files[0]) == ["etc/caddy/Caddyfile", *served_too]
    # Everything was asked: the cases, and every path Caddy's reading names, without and with a service behind.
    named = len(TRY.named(reading(), HOSTS))
    assert len(a_run.asked) == len(TRY.alone(b"")) + len(TRY.behind()) + 2 * named
    assert [asked.path for asked in a_run.asked].count("/.well-known/openid-credential-issuer/pid") == 2
    assert a_run.out.count("a path the Caddyfile names") == 2 * named
    assert a_run.out.index("nothing behind Caddy") < a_run.out.index("a service behind Caddy")
    assert a_run.behind == [[("cunho-course", 8000), ("cunho-pid", 8000), ("demo", 8000)]]
    assert a_run.poked == [49153], "and a client that speaks no TLS came by"
    assert a_run.asked_before_the_log == 0, "the log is read before the first thing is asked"
    assert a_run.held == a_run.behind, "every name is held inside the run, and the stand-in answers under each"
    assert a_run.did == [
        ("Caddy's reading is taken", 0),  # before Caddy is started, of a Caddy that starts no server
        ("the names are held", 0),  # and those before Caddy is started too, so that it looks for none outside the run
        ("Caddy is started", 0),
        ("the log is read for the first time", 0),
        ("a service is put behind", len(TRY.alone(b"")) + len(TRY.named(reading(), HOSTS))),
    ]
    assert a_run.entered == a_run.left == 1, "one Caddy, and it is removed at the end of a run that went well"
    assert a_run.asked_before_the_stand_in == len(TRY.alone(b"")) + named, "nothing stands behind Caddy at first"
    assert 1 <= a_run.read_at - a_run.poked_at <= 3, "Caddy is given a moment to write before its log is read"
    # What it says of the run, from its first line to its last.
    first = f"Caddy {TRY.service(COMPOSE)}\non {ROOT / 'deploy' / 'Caddyfile'}\n"
    names = f"as {HOSTS['issuer']} and {HOSTS['demo']}\n\n"
    assert a_run.out.startswith(first + names + "what Caddy makes of the file\n")
    assert "\nwrote nothing while it was asked.\nWhat was tried, for TRIED in tests/test_deploy.py:\n" in a_run.out


def test_a_method_of_more_than_eight_letters_is_shortened_in_its_line(a_run: Run) -> None:
    more = {"match": [{"path": ["/dav"], "method": ["PROPFIND", "PROPPATCH"]}], "handle": [respond(207)]}
    routes_of(a_run.config, DEMO).insert(1, more)
    assert a_run() == 0
    assert "\n  ok  PROPFIND   demo   /dav " in a_run.out and "\n  ok  PRO...(9)  demo   /dav " in a_run.out


def test_one_answer_that_is_not_right_and_it_does_not_hold(a_run: Run) -> None:
    a_run.ask = lambda asked: answer(200, ()) if asked.stand_in == "switch" else right(asked)
    assert a_run() == 1
    assert "\nIt does not hold: 1 answer does not carry the two headers as they must.\n" in a_run.out
    assert (
        f"  NO  {'GET':<10} issuer /pid/tried" in a_run.out and "      strict-transport-security 0 times" in a_run.out
    )
    assert "for TRIED" not in a_run.out, "no digest for what did not hold"


def test_every_answer_that_is_not_right_is_counted_once(a_run: Run) -> None:
    a_run.ask = lambda asked: answer(500, ()) if asked.path == "/crl/iaca.crl" else right(asked)
    assert a_run() == 1
    assert (
        "\nIt does not hold: 5 answers do not carry the two headers as they must.\n" in a_run.out
    )  # three cases, and the path named, twice


def test_an_answer_that_cannot_be_read_and_a_connection_closed_where_an_answer_was_due(a_run: Run) -> None:
    a_run.ask = lambda asked: None if asked.path == "/no-such-thing" else right(asked)
    assert a_run() == 2 and "an answer that cannot be read" in a_run.out and "\n  ??  GET " in a_run.out
    a_run.ask = lambda asked: TRY.NOTHING if asked.why == "a path no rule knows" else right(asked)
    assert a_run() == 2 and "no answer: the connection was closed" in a_run.out and "It does not hold" not in a_run.out
    # Where the Caddyfile names a path and closes the connection for it, there is no answer to carry a header.
    a_run.ask = lambda asked: TRY.NOTHING if asked.why == "a path the Caddyfile names" else right(asked)
    assert a_run() == 0
    widest = max(len(asked.path) for asked in a_run.asked)
    no_status = f"\n  ok  {'GET':<10} issuer {'/pid':<{widest}}      a path the Caddyfile names\n"
    assert no_status in a_run.out, "three blanks where a status would stand"


@pytest.mark.parametrize("line", [CUT_SHORT, PATH_ONLY, "a line that is no JSON and names nobody"])
def test_one_line_written_while_caddy_was_asked_and_it_does_not_hold_whatever_it_says(a_run: Run, line: str) -> None:
    a_run.lines = (line,)
    assert a_run() == 1
    assert "Caddy's log: 1 line written while it was asked\n" in a_run.out and line[:200] in a_run.out
    assert "\nIt does not hold: Caddy wrote 1 line while it was asked.\n" in a_run.out
    assert "for TRIED" not in a_run.out


def test_the_lines_written_are_shown_as_they_are_the_first_dozen_of_them(a_run: Run) -> None:
    a_run.lines = (CUT_SHORT, "x" * 600, *(f"line {number} of many" for number in range(3, 15)))
    assert a_run() == 1
    assert "Caddy's log: 14 lines written while it was asked\n" in a_run.out
    assert f"\n  {CUT_SHORT}\n  {'x' * 500}\n  line 3 of many\n" in a_run.out, "five hundred characters of each"
    assert "  line 12 of many\n" in a_run.out and "line 13 of many" not in a_run.out
    assert "\nIt does not hold: Caddy wrote 14 lines while it was asked.\n" in a_run.out


@pytest.mark.parametrize("after", [1, 5, 27, 28, 40, 58])
def test_a_line_counts_whenever_it_is_written_while_caddy_is_asked(a_run: Run, after: int) -> None:
    # After the first thing asked, in the first half, at its end, as the second begins, in it, after the last.
    a_run.line_after = {after: CUT_SHORT}
    assert a_run() == 1 and len(a_run.asked) == 58
    assert len(TRY.alone(b"")) + len(TRY.named(reading(), HOSTS)) == 27, "where the first half ends"
    assert "\nIt does not hold: Caddy wrote 1 line while it was asked.\n" in a_run.out


def test_an_answer_with_both_headers_that_is_not_the_one_a_case_expects_gets_no_digest_and_is_not_called_a_loss(
    a_run: Run,
) -> None:
    # The operator API answered with 403 where it answers 404 today: the two headers are there, the case is not met.
    a_run.ask = lambda asked: answer(403) if asked.path == "/pid/admin/offers" else right(asked)
    assert a_run() == 2
    assert (
        f"\n  ??  {'GET':<10} issuer /pid/admin/offers" in a_run.out and "\n      answered 403, not 404\n" in a_run.out
    )
    said = "\nIt is not known to hold. No answer lacked a header and Caddy wrote nothing while it was asked, but:\n"
    said += "  1 case was not answered as this tool expects of the stack (?? above):\n"
    said += "  its cases no longer fit the Caddyfile, and have to be changed with it before it can vouch for it.\n"
    assert a_run.out.endswith(said) and "It does not hold" not in a_run.out and "for TRIED" not in a_run.out
    # Two such cases, and a reading that is not known besides: both are said.
    a_run.config["admin"] = {}
    a_run.ask = lambda asked: answer(403) if asked.status == 404 else right(asked)
    assert a_run() == 2
    api = "Caddy's own API is not off: what Caddy is told can then be changed while it runs"
    assert a_run.out.endswith(
        "  5 cases were not answered as this tool expects of the stack (?? above).\n"
        f"  Caddy reads the file in a way this tool does not know: {api}.\n"
    ), "which of the two it is that the cases do not fit, it does not say"
    # And an answer that lacks a header is a loss whatever else is said of it.
    a_run.ask = lambda asked: answer(403, ()) if asked.path == "/pid/admin/offers" else right(asked)
    assert a_run() == 1 and f"\n  NO  {'GET':<10} issuer /pid/admin/offers" in a_run.out


def test_what_caddy_wrote_before_it_was_asked_is_not_held_against_it(a_run: Run) -> None:
    a_run.before = (["a line to stdout"], [*AT_THE_START, CUT_SHORT])
    assert a_run() == 0


def test_an_access_log_that_is_on_and_it_does_not_hold_whatever_is_written(a_run: Run) -> None:
    server_of(a_run.config)["logs"] = {"logger_names": {HOSTS["issuer"]: ["log0"]}}
    a_run.config["logging"]["logs"]["log0"] = {"writer": {"output": "discard"}, "include": ["http.log.access.log0"]}
    assert a_run() == 1
    assert "  NO  an access log is on\n" in a_run.out and "\nIt does not hold: an access log is on.\n" in a_run.out
    assert "  ??  " not in a_run.out, "that a server has a part for its logs is no part without a rule"
    assert "  ok  " not in a_run.out.split("nothing behind Caddy")[0], "nothing is called known beside it"
    assert "for TRIED" not in a_run.out
    a_run.lines = (ACCESS, ACCESS)
    a_run.ask = lambda asked: answer(200, ()) if asked.stand_in == "boom" else right(asked)
    assert a_run() == 1
    told = "an access log is on, and 3 answers do not carry the two headers as they must, and Caddy wrote 2 lines"
    assert f"\nIt does not hold: {told} while it was asked.\n" in a_run.out


def test_a_reading_that_is_not_known_to_hold_gets_no_digest_though_nothing_asked_went_wrong(a_run: Run) -> None:
    routes_of(a_run.config, DEMO).insert(1, {"handle": [{"handler": "encode"}]})
    a_run.config["admin"] = {"listen": "localhost:2019"}
    assert a_run() == 2
    assert (
        "(the handler encode), for which this tool has no rule\n" in a_run.out and "  ??  Caddy's own API" in a_run.out
    )
    said = "\nIt is not known to hold. No answer lacked a header and Caddy wrote nothing while it was asked, but:\n"
    assert said in a_run.out
    assert "\n  Caddy reads the file in a way this tool does not know: Caddy's own API is not off" in a_run.out
    assert "(the handler encode), for which this tool has no rule.\n" in a_run.out
    assert "It holds" not in a_run.out and "for TRIED" not in a_run.out and "  ok  the two headers" not in a_run.out
    assert "not answered as this tool expects" not in a_run.out, "no case was off: nothing is said of the cases"
    assert len(a_run.asked) > 50, "it was asked all the same: what goes wrong is worth knowing"


def test_a_reading_that_is_not_known_and_an_answer_that_is_not_right_and_it_does_not_hold(a_run: Run) -> None:
    routes_of(a_run.config, DEMO).insert(1, {"handle": [{"handler": "encode"}]})
    a_run.ask = lambda asked: answer(200, ()) if asked.host == "demo" else right(asked)
    assert a_run() == 1
    assert (
        "(the handler encode), for which this tool has no rule\n" in a_run.out and "\nIt does not hold: " in a_run.out
    )


def test_a_caddyfile_elsewhere_is_tried_as_it_is_and_its_digest_is_said_to_be_its_own(
    a_run: Run, tmp_path: Path
) -> None:
    other = tmp_path / "Caddyfile"
    other.write_bytes(CADDYFILE.replace("\n", "\r\n").encode() + b"# and one more comment\r\n")
    assert a_run("--caddyfile", str(other)) == 0
    assert a_run.files[0]["etc/caddy/Caddyfile"] == other.read_bytes(), "Caddy gets the file byte for byte"
    assert f'"{TRY.CADDYFILE}": "{TRY.digests(CADDYFILE, COMPOSE)[TRY.CADDYFILE]}",' in a_run.out, "it says the same"
    assert f"The first is the digest of {other}, which is not deploy/Caddyfile.\n" in a_run.out


def test_the_digest_printed_is_that_of_the_file_that_was_tried(
    a_run: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    says_more = with_a_line("\tgrace_period 5s\n")
    other = tmp_path / "Caddyfile"
    other.write_text(says_more, encoding="utf-8")
    reads: list[Path] = []
    as_it_is = Path.read_bytes

    def once(path: Path) -> bytes:
        """What a pipe gives: the file the first time it is read, and nothing after that."""
        reads.append(path)
        return as_it_is(path) if path != other or reads.count(other) == 1 else b""

    monkeypatch.setattr(Path, "read_bytes", once)
    assert a_run("--caddyfile", str(other)) == 0
    its_own = TRY.digests(says_more, COMPOSE)[TRY.CADDYFILE]
    assert its_own != TRY.digests(CADDYFILE, COMPOSE)[TRY.CADDYFILE]
    assert f'"{TRY.CADDYFILE}": "{its_own}",' in a_run.out, "of what was tried, not of the stack's file"
    assert TRY.digests(CADDYFILE, COMPOSE)[TRY.CADDYFILE] not in a_run.out
    assert a_run.files[0]["etc/caddy/Caddyfile"] == says_more.encode(), (
        "and Caddy got the very bytes it is the digest of"
    )
    assert reads.count(other) == 1, (
        "the file is read once: what is looked at, digested and given to Caddy is one reading"
    )


def test_a_caddyfile_that_passes_requests_on_to_nothing_gets_no_stand_in(a_run: Run) -> None:
    for host, block in ((ISSUER, 3), (ISSUER, 4), (DEMO, 2)):
        routes_of(a_run.config, host)[block]["handle"][0]["routes"][0]["handle"] = [respond(200)]
    assert a_run() == 0 and a_run.behind == [] and a_run.held == []


def test_a_service_caddy_goes_on_trying_for_too_long_cannot_be_tried(a_run: Run) -> None:
    a_proxy(a_run.config).update(load_balancing={"try_duration": 30000000000})
    assert a_run() == 2
    assert a_run.err == (
        "It could not be tried: the Caddyfile has Caddy go on trying a service that is away for 30 seconds "
        "(try_duration): too long for this tool, which waits 15 for an answer\n"
    )
    assert a_run.asked == [] and a_run.did == [("Caddy's reading is taken", 0)]
    a_proxy(a_run.config)["load_balancing"]["try_duration"] = 14000000000  # an answer after 14 seconds comes too late
    assert a_run() == 2 and "for 14 seconds" in a_run.err
    a_proxy(a_run.config)["load_balancing"]["try_duration"] = 13000000000
    assert a_run() == 0
    a_proxy(a_run.config)["load_balancing"]["try_duration"] = "13s"  # a time written as a text is not read here
    assert a_run() == 2 and "is not of the shape this tool reads" in a_run.err


def test_a_service_spoken_to_as_the_stand_in_does_not_speak_and_nothing_is_asked(a_run: Run) -> None:
    a_proxy(a_run.config).update(transport={"protocol": "fastcgi"})
    assert a_run() == 2
    assert a_run.err == (
        "It could not be tried: the Caddyfile passes requests on in a way this tool has no stand-in for (transport)\n"
    )
    assert "handle[0].transport.protocol (a way of speaking to a service that is not plain HTTP)" in a_run.out
    assert a_run.asked == [] and a_run.held == [] and "It holds" not in a_run.out
    assert a_run.did == [("Caddy's reading is taken", 0)], "what it read is said, and Caddy is not started on it"


@pytest.mark.parametrize(
    ("line", "why"),
    [
        (
            "\trespond /a \\\n\t\t200\n",
            "the Caddyfile has a backslash, and this tool takes none, since one can join a line to the next: "
            "respond /a \\. It is read line by line here, and has to be plain",
        ),
        ('\trespond "one\n\ttwo" 200\n', 'the Caddyfile has a " that is not around one whole word of one line'),
        (
            "\timport more/*.caddy\n",
            "the Caddyfile has an import this tool does not follow (import more/*.caddy). It follows `import name` "
            "and no more, for a snippet the file itself opens with `(name) {`",
        ),
        (
            "\timport headers /pid/*\n",
            "the Caddyfile has an import this tool does not follow (import headers /pid/*). It follows",
        ),
    ],
)
def test_a_caddyfile_that_is_not_read_line_by_line_is_not_tried(
    a_run: Run, tmp_path: Path, line: str, why: str
) -> None:
    (tmp_path / "Caddyfile").write_text(with_a_line(line), encoding="utf-8")
    assert a_run("--caddyfile", str(tmp_path / "Caddyfile")) == 2
    assert a_run.err.startswith(f"It could not be tried: {why}") and "It holds" not in a_run.out
    assert a_run.docker.ran == [] and a_run.files == [], "before anything is started"


@pytest.mark.parametrize(
    "change",
    [
        lambda c: server_of(c).update(routes=5),
        lambda c: server_of(c).update(errors=["no", "names"]),
        lambda c: routes_of(c, DEMO).append("no route"),
        lambda c: routes_of(c, DEMO)[1].update(handle=["no handler"]),
        lambda c: routes_of(c, DEMO)[1].update(match=["no matcher"]),
        lambda c: a_proxy(c).update(handle_response=["no answer"]),
    ],
)
def test_a_reading_that_is_not_of_the_shape_the_tool_reads_cannot_be_tried(
    a_run: Run, change: Callable[[Any], Any]
) -> None:
    change(a_run.config)
    assert a_run() == 2
    assert a_run.err == "It could not be tried: what Caddy made of the Caddyfile is not of the shape this tool reads\n"
    assert a_run.asked == [] and "It holds" not in a_run.out


def test_a_reading_out_of_shape_where_its_servers_stand_or_too_deep_to_follow_cannot_be_tried(a_run: Run) -> None:
    out_of_shape = "It could not be tried: what Caddy made of the Caddyfile is not of the shape this tool reads\n"
    for servers in ({"srv0": "a text"}, {"srv0": ["a list"]}, {"srv0": {"protocols": 7}}):
        a_run.config["apps"]["http"]["servers"] = servers
        assert a_run() == 2 and a_run.err == out_of_shape, servers
    a_run.config = reading()
    inside: Any = respond(200)
    for _ in range(1000):
        inside = {"handler": "subroute", "routes": [{"handle": [inside]}]}
    routes_of(a_run.config, DEMO).append({"handle": [inside]})
    assert a_run() == 2 and a_run.err == out_of_shape


def test_a_caddy_told_not_to_speak_http_1_1_cannot_be_asked(a_run: Run) -> None:
    server_of(a_run.config)["protocols"] = ["h2"]
    assert a_run() == 2
    assert "leaves HTTP/1.1 out of what Caddy speaks, and this tool speaks nothing else" in a_run.err
    assert a_run.asked == []
    server_of(a_run.config).pop("protocols")  # left unsaid, Caddy speaks it
    assert a_run() == 0


def test_a_service_no_stand_in_can_be_put_at_and_it_is_not_tried(a_run: Run) -> None:
    routes_of(a_run.config, DEMO)[2]["handle"][0]["routes"][0]["handle"] = [proxy("unix//run/demo.sock")]
    assert a_run() == 2
    assert "passes requests on to unix//run/demo.sock, where this tool puts no stand-in" in a_run.err
    assert a_run.asked == [] and "It holds" not in a_run.out


def test_what_stands_in_the_way_of_a_run_is_said_and_it_does_not_pass(a_run: Run) -> None:
    def gives_way(rig: Any) -> Any:
        raise TRY.CannotTry("Caddy gave no answer to GET / of the demo host within 15 seconds")

    a_run.config = gives_way
    assert a_run() == 2
    assert a_run.err == "It could not be tried: Caddy gave no answer to GET / of the demo host within 15 seconds\n"
    assert "It holds" not in a_run.out


@pytest.mark.parametrize("ignored", [(signal.SIGHUP,), (signal.SIGINT,), TRY.STOPS])
def test_a_signal_it_was_started_to_ignore_stays_ignored(a_run: Run, ignored: tuple[int, ...]) -> None:
    a_run.ignored = ignored  # a hangup under nohup, a Ctrl-C for what a script put in the background
    assert a_run() == 0 and a_run.entered == a_run.left == 1


@pytest.mark.parametrize("kind", [RuntimeError, ValueError, OSError, ZeroDivisionError, RecursionError])
def test_a_fault_of_the_tool_itself_is_no_verdict(a_run: Run, kind: type[Exception]) -> None:
    def goes_wrong(rig: Any) -> Any:
        raise kind("something this tool did not foresee")

    a_run.config = goes_wrong
    assert a_run() == 2, "and not 1, which says that it does not hold"
    assert a_run.err.startswith("Traceback (most recent call last):\n")
    assert f"{kind.__name__}: something this tool did not foresee\n" in a_run.err
    assert a_run.err.endswith(
        "It could not be tried: this tool went wrong, as shown above. Nothing is known from it.\n"
    )
    assert "It holds" not in a_run.out and "It does not hold" not in a_run.out


@pytest.mark.parametrize(
    "ends", [TRY.CannotTry("Caddy gave no answer"), KeyboardInterrupt(), RuntimeError("not foreseen")], ids=repr
)
def test_what_it_had_printed_is_out_before_it_says_why_it_ended(a_run: Run, ends: BaseException) -> None:
    """Its two streams may go to one place, a terminal or a file. What it printed of the run has to be there
    before the line that says why it went no further, however it ended."""

    def at_the_second(asked: Any) -> Any:
        if len(a_run.asked) == 2:
            raise ends
        return right(asked)

    a_run.ask, a_run.streams = at_the_second, []
    assert a_run() in (2, 130)
    noted = a_run.streams or []
    last_printed = len(noted) - 1 - noted[::-1].index("stdout written")
    said_why = noted.index("stderr written")
    assert last_printed < said_why and "stdout flushed" in noted[last_printed:said_why], noted[last_printed:]


@pytest.mark.parametrize(
    ("ends", "code"),
    [(None, 0), (TRY.CannotTry("Caddy gave no answer"), 2), (KeyboardInterrupt(), 130), (RuntimeError("a fault"), 2)],
    ids=repr,
)
def test_with_nowhere_to_print_to_it_ends_as_it_would_have(a_run: Run, ends: BaseException | None, code: int) -> None:
    """Started with its standard output closed, Python has none. That is no reason to end in 1, which says that
    it does not hold."""

    def at_the_second(asked: Any) -> Any:
        if ends is not None and len(a_run.asked) == 2:
            raise ends
        return right(asked)

    a_run.ask, a_run.nowhere = at_the_second, True
    assert a_run() == code and a_run.out == ""
    assert a_run.left == a_run.entered == 1


def test_when_nobody_reads_what_it_prints_any_more_it_ends_and_says_so(a_run: Run) -> None:
    class Gone:
        """Standard output whose reader has left: a pipe to `head`, a pager that was quit."""

        def write(self, text: str) -> int:
            raise BrokenPipeError(32, "Broken pipe")

        def flush(self) -> None:
            raise BrokenPipeError(32, "Broken pipe")

        def fileno(self) -> int:
            raise OSError("no file behind it here")

    a_run.printed_to = Gone()
    assert a_run() == 2, "there is nobody to give a verdict to"
    assert a_run.err == "It could not be tried to its end: nobody reads what it prints any more.\n"
    assert a_run.left == a_run.entered == 1, "and what it started is removed"


def test_a_reader_that_left_before_the_verdict_was_out_is_found_at_the_end(a_run: Run) -> None:
    class LeftAtTheEnd:
        """Standard output that keeps what is printed until it is full or flushed, as a pipe does, and whose
        reader has gone by the time the verdict is to go out."""

        def __init__(self) -> None:
            self.kept = ""

        def write(self, text: str) -> int:
            self.kept += text
            return len(text)

        def flush(self) -> None:
            if "It holds" in self.kept:
                raise BrokenPipeError(32, "Broken pipe")

        def fileno(self) -> int:
            raise OSError("no file behind it here")

    a_run.printed_to = LeftAtTheEnd()
    assert a_run() == 2, "a verdict that reached nobody is not one that was given"
    assert a_run.err == "It could not be tried to its end: nobody reads what it prints any more.\n"


def test_a_stream_that_is_let_go_takes_what_is_written_to_it_and_gives_it_to_nobody() -> None:
    with open(no_reader(), "w", encoding="utf-8") as stream:
        stream.write("what was still to be written\n")
        with pytest.raises(BrokenPipeError):
            stream.flush()
        TRY.let_go(stream)
        stream.flush()  # as Python does for the two streams of a process when it ends
    for nothing_behind_it in (None, io.StringIO()):
        TRY.let_go(nothing_behind_it)


@pytest.mark.parametrize("buffering", [-1, 1], ids=["lines kept back", "each line written at once"])
def test_what_cannot_be_said_on_standard_error_raises_nothing_and_is_let_go(
    monkeypatch: pytest.MonkeyPatch, buffering: int
) -> None:
    """An error raised while a run says why it ended would end the process in 1, as if it did not hold. And what
    stays unwritten would end it in 120."""
    with open(no_reader(), "w", buffering=buffering, encoding="utf-8") as stream:
        monkeypatch.setattr(sys, "stderr", stream)
        TRY.warned("It could not be tried: for a reason nobody reads")
        stream.flush()  # nothing is left that cannot be written


def test_with_no_standard_error_what_a_run_could_not_do_is_said_to_nobody(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    closed = io.StringIO()
    closed.close()
    for stream in (None, closed):
        monkeypatch.setattr(sys, "stderr", stream)
        TRY.warned("It could not be tried: for a reason")
    monkeypatch.undo()
    assert capsys.readouterr() == ("", ""), "and not on standard output in its place"


@pytest.mark.parametrize("code", [2, 130])
def test_what_a_run_printed_is_let_go_when_it_ends_with_nobody_reading_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], code: int
) -> None:
    with open(no_reader(), "w", encoding="utf-8") as stream:
        monkeypatch.setattr(sys, "stdout", stream)
        print("what the run printed")
        assert TRY.ended(code, "why it ended") == code
        stream.flush()
    monkeypatch.undo()
    assert capsys.readouterr() == ("", "why it ended\n")


def test_stopped_before_its_end_it_says_that_nothing_is_known(a_run: Run) -> None:
    def stopped(rig: Any) -> Any:
        TRY.stopped(signal.SIGTERM, None)

    a_run.config = stopped
    assert a_run() == 130
    assert a_run.err == "It was stopped before its end, and nothing is known from it.\n" and "It holds" not in a_run.out


# when it cannot be tried -----------------------------------------------------------------------------------------


def test_without_docker_it_says_so_and_does_not_pass(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def no_docker(*args: Any, **kwargs: Any) -> Any:
        raise FileNotFoundError("docker")

    monkeypatch.setattr(TRY.subprocess, "Popen", no_docker)
    monkeypatch.setattr(sys, "argv", ["try_caddy.py"])
    assert TRY.main() == 2
    assert capsys.readouterr().err == "It could not be tried: Docker is needed, and there is no docker command here\n"


def test_a_docker_that_does_not_answer_is_not_taken_for_a_missing_image(a_run: Run) -> None:
    a_run.docker.answers["version"] = (
        1,
        b"",
        b"Cannot connect to the Docker daemon at unix:///var/run/docker.sock\xff\n",
    )
    assert a_run() == 2
    assert a_run.err == (
        "It could not be tried: Docker does not answer: Cannot connect to the Docker daemon at "
        "unix:///var/run/docker.sock\ufffd\n"
    )
    assert [args[0] for args in a_run.docker.ran] == ["version"] and a_run.files == []


def test_an_image_that_is_not_here_is_not_fetched_unasked(a_run: Run) -> None:
    a_run.docker.answers["image_inspect"] = (1, b"", b"Error response from daemon: No such image: caddy@sha256:0c22\n")
    assert a_run() == 2
    assert f"the image {TRY.service(COMPOSE)} is not on this machine: --pull fetches it" in a_run.err
    assert [args[0] for args in a_run.docker.ran] == ["version", "image"], "it looked for the image and did no more"
    assert a_run.files == []
    a_run.docker.ran.clear()
    assert a_run("--pull") == 0
    assert a_run.docker.ran[-1] == ("pull", TRY.service(COMPOSE)) and a_run.docker.how[-1]["wait"] == 540


def test_a_docker_that_cannot_look_at_the_image_is_not_taken_for_a_missing_image(a_run: Run) -> None:
    a_run.docker.answers["image_inspect"] = (1, b"", b"Error response from daemon: layer does not exist\n")
    assert a_run("--pull") == 2
    assert (
        a_run.err == "It could not be tried: docker image inspect: Error response from daemon: layer does not exist\n"
    )
    assert [args[0] for args in a_run.docker.ran] == ["version", "image"], "nothing is fetched for that"


def test_an_image_that_is_here_is_not_fetched_again(a_run: Run) -> None:
    assert a_run("--pull") == 0
    assert [args[0] for args in a_run.docker.ran] == ["version", "image"]


def test_a_compose_file_that_is_no_text_or_reads_two_ways_is_refused_before_anything_is_started(
    a_run: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A copy of the few files the tool reads, with another compose file.
    metadata = tmp_path / "demo" / "metadata" / "course" / "type_metadata"
    metadata.mkdir(parents=True)
    (metadata / "course-certificate-1.json").write_bytes(b"{}")
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "Caddyfile").write_bytes((ROOT / "deploy" / "Caddyfile").read_bytes())
    monkeypatch.setattr(TRY, "ROOT", tmp_path)
    (tmp_path / "deploy" / "compose.yaml").write_bytes(COMPOSE.replace("\n", "\r\n").encode())
    assert a_run() == 0, "with the line ends a Windows checkout gives it, it says the same"
    for name, digest in TRY.digests(CADDYFILE, COMPOSE).items():
        assert f'    "{name}": "{digest}",\n' in a_run.out
    a_run.docker.ran.clear()
    a_run.files.clear()
    (tmp_path / "deploy" / "compose.yaml").write_bytes(COMPOSE.encode() + b"\xff")
    assert a_run() == 2
    assert a_run.err.startswith("It could not be tried: deploy/compose.yaml is not text: "), "the file is named"
    hidden = COMPOSE.replace(
        "    cap_add: [NET_BIND_SERVICE]\n", "    cap_add: [NET_BIND_SERVICE]\u2028    command: x\n"
    )
    (tmp_path / "deploy" / "compose.yaml").write_text(hidden, encoding="utf-8")
    assert a_run() == 2
    refused = (
        "It could not be tried: the compose file has a character that does not print ('\\u2028'): its caddy service"
    )
    assert a_run.err.startswith(refused) and a_run.docker.ran == [] and a_run.files == []


def test_a_caddyfile_that_cannot_be_read_is_not_tried_and_does_not_pass(a_run: Run, tmp_path: Path) -> None:
    assert a_run("--caddyfile", str(tmp_path / "absent")) == 2
    assert "a file it needs could not be read" in a_run.err and "absent" in a_run.err
    assert a_run("--caddyfile", str(tmp_path)) == 2
    assert "a file it needs could not be read" in a_run.err
    (tmp_path / "not-text").write_bytes(b"{\n\xff\xfe\n}\n")
    assert a_run("--caddyfile", str(tmp_path / "not-text")) == 2
    assert a_run.err.startswith(f"It could not be tried: {tmp_path / 'not-text'} is not text: ")
    assert a_run.docker.ran == []


def test_run_as_a_script_it_ends_with_what_it_found(tmp_path: Path) -> None:
    (tmp_path / "Caddyfile").write_text(with_a_line("\timport more/*.caddy\n"), encoding="utf-8")
    script = [sys.executable, str(ROOT / "tools" / "try_caddy.py"), "--caddyfile", str(tmp_path / "Caddyfile")]
    done = subprocess.run(script, capture_output=True, text=True, timeout=60)
    assert done.returncode == 2 and done.stdout == ""
    assert done.stderr.startswith("It could not be tried: the Caddyfile has an import this tool does not follow")


PLAYED_DOCKER = r"""#!/bin/sh
# Docker, played for the tool when it runs as a process: every command is noted, and a few are answered.
echo "$*" >> "$PLAYED_RAN"
case "$1 $3" in
"port "*) echo "127.0.0.1:$PLAYED_PORT" ;;
"run -i")
  while [ -n "$PLAYED_WAITS" ] && [ ! -e "$PLAYED_WAITS" ]; do sleep 0.05; done
  cat "$PLAYED_READING"
  ;;
"exec sh") if [ -n "$PLAYED_HANGS" ]; then exec sleep 60; fi ;;
esac
"""


# A reading that names no service this tool can stand in for: it is told after all that the reading showed.
NO_NAME = {"apps": {"http": {"servers": {"srv0": {"routes": [{"handle": [proxy("unix//run/demo.sock")]}]}}}}}
NO_STAND_IN = (
    "It could not be tried: the Caddyfile passes requests on to unix//run/demo.sock, where this tool puts no stand-in"
)


def no_reader() -> int:
    """The writing end of a pipe that nobody reads any more: what `| head` leaves a program with."""
    reading, writing = os.pipe()
    os.close(reading)
    return writing


class Process:
    """The tool run as a process of its own, on the stack's Caddyfile, with a script for Docker and with the server
    of these tests where Docker would publish Caddy. Both of its streams come back as one, in the order written."""

    def __init__(
        self,
        tmp_path: Path,
        certificate: Path,
        reading_given: Any,
        hangs: bool = False,
        waits: bool = False,
        at_once: bool = False,
        out: int = subprocess.PIPE,
        err: int = subprocess.STDOUT,
    ) -> None:
        self.go_on = tmp_path / "go-on"  # with `waits`, Caddy's reading is not given before this file is there
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "docker").write_text(PLAYED_DOCKER, encoding="utf-8")
        (tmp_path / "bin" / "docker").chmod(0o755)
        (tmp_path / "reading.json").write_text(json.dumps(reading_given), encoding="utf-8")
        self.ran = tmp_path / "ran"
        self.ran.write_text("", encoding="utf-8")
        self.caddy = Played(certificate, lambda tls: None)
        env = {
            **os.environ,
            "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
            "PLAYED_RAN": str(self.ran),
            "PLAYED_PORT": str(self.caddy.port),
            "PLAYED_READING": str(tmp_path / "reading.json"),
            "PLAYED_HANGS": "yes" if hangs else "",
            "PLAYED_WAITS": str(self.go_on) if waits else "",
            "PYTHONUNBUFFERED": "yes" if at_once else "",  # whether Python writes each line out as it is printed
        }
        script = [sys.executable, str(ROOT / "tools" / "try_caddy.py")]
        self.process = subprocess.Popen(script, env=env, stdout=out, stderr=err, text=True)

    def commands(self) -> list[str]:
        return [line for line in self.ran.read_text(encoding="utf-8").split("\n") if line]

    def until_it_hangs(self) -> None:
        """Wait until it is at the line it writes to Caddy's log, where the played Docker does not come back."""
        waited = time.monotonic() + 30
        while not any(" sh -c " in command for command in self.commands()):
            assert time.monotonic() < waited and self.process.poll() is None
            time.sleep(0.05)

    def reader_leaves(self) -> None:
        """Whoever read what it prints has seen its first line, which it writes out at once, and reads no more."""
        assert self.process.stdout is not None
        assert self.process.stdout.readline().startswith("Caddy caddy@sha256:")
        self.process.stdout.close()

    def ended(self) -> tuple[int, str, str]:
        """How it ended, and what it wrote to each of its streams, as far as that is read here."""
        out, err = self.process.communicate(timeout=60)
        self.caddy.close()
        return self.process.returncode, out or "", err or ""


@needs_sh
def test_as_a_process_what_it_printed_comes_before_why_it_could_not_go_on(tmp_path: Path, certificate: Path) -> None:
    code, out, _ = Process(tmp_path, certificate, NO_NAME).ended()
    lines = out.rstrip("\n").split("\n")
    assert code == 2
    assert lines[0].startswith("Caddy caddy@sha256:") and lines[4] == "what Caddy makes of the file"
    assert lines[5].startswith("  ??  ") and lines[-2].startswith("  ??  "), "all it had to say comes first"
    assert lines[-1] == NO_STAND_IN


@needs_sh
@pytest.mark.parametrize("number", TRY.STOPS, ids=lambda number: signal.Signals(number).name)
def test_as_a_process_a_signal_to_end_removes_what_was_started_and_says_so(
    tmp_path: Path, certificate: Path, number: int
) -> None:
    run = Process(tmp_path, certificate, {}, hangs=True)
    run.until_it_hangs()
    run.process.send_signal(number)
    code, out, _ = run.ended()
    assert code == 130
    assert out.rstrip("\n").split("\n")[-1] == "It was stopped before its end, and nothing is known from it."
    assert out.index("what Caddy makes of the file") < out.index("It was stopped"), "what it had printed comes first"
    commands = run.commands()
    name = next(command for command in commands if command.startswith("network create")).split()[-1]
    assert name.startswith("try-caddy-")
    removed = [f"rm -f -v {name}-{part}" for part in ("reading", "caddy", "service")]
    assert commands[-4:] == [*removed, f"network rm {name}"]


@needs_sh
def test_as_a_process_with_nobody_reading_what_it_prints_it_ends_as_it_would_have(
    tmp_path: Path, certificate: Path
) -> None:
    """`try_caddy.py | head`, once head has read enough. What is printed after that cannot be written out. Python
    tries once more as the process ends, and ends it in 120 with a complaint of its own when that fails again."""
    run = Process(tmp_path, certificate, NO_NAME, waits=True, err=subprocess.PIPE)
    run.reader_leaves()
    run.go_on.write_text("", encoding="utf-8")
    assert run.ended() == (2, "", f"{NO_STAND_IN}\n")


@needs_sh
@pytest.mark.parametrize("at_once", [False, True], ids=["lines kept back", "each line written at once"])
def test_as_a_process_with_nobody_reading_either_stream_it_does_not_end_as_if_it_did_not_hold(
    tmp_path: Path, certificate: Path, at_once: bool
) -> None:
    """`try_caddy.py 2>&1 | head`. Why it ended cannot be said either. An error raised over that would end the
    process in 1, which is how "It does not hold" ends: it is raised at once where Python is told to keep no line
    back, as it is in many a pipeline."""
    gone = no_reader()
    run = Process(tmp_path, certificate, NO_NAME, at_once=at_once, out=gone, err=gone)
    os.close(gone)
    assert run.ended() == (2, "", "")


@needs_sh
@pytest.mark.parametrize("at_once", [False, True], ids=["lines kept back", "each line written at once"])
def test_as_a_process_with_no_reader_from_the_start_it_finds_that_out_at_its_first_line(
    tmp_path: Path, certificate: Path, at_once: bool
) -> None:
    gone = no_reader()
    run = Process(tmp_path, certificate, NO_NAME, at_once=at_once, out=gone, err=subprocess.PIPE)
    os.close(gone)
    assert run.ended() == (2, "", "It could not be tried to its end: nobody reads what it prints any more.\n")
    commands = run.commands()
    assert [command.split()[0] for command in commands[-4:]] == ["rm", "rm", "rm", "network"], commands


@needs_sh
def test_as_a_process_stopped_with_nobody_reading_what_it_prints_it_ends_as_stopped(
    tmp_path: Path, certificate: Path
) -> None:
    run = Process(tmp_path, certificate, {}, hangs=True, err=subprocess.PIPE)
    run.reader_leaves()
    run.until_it_hangs()
    run.process.send_signal(signal.SIGTERM)
    assert run.ended() == (130, "", "It was stopped before its end, and nothing is known from it.\n")


def test_asked_for_help_it_says_what_it_is_for(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["try_caddy.py", "--help"])
    with pytest.raises(SystemExit) as ended:
        TRY.main()
    said = " ".join(capsys.readouterr().out.split())
    assert ended.value.code == 0 and "Try what Caddy is told on a running Caddy: every answer of the two hosts" in said
    assert "--caddyfile CADDYFILE" in said and "--pull" in said and "--keep" in said
    assert "It starts the Caddy" not in said, "the first lines of what it says of itself, and no more"
