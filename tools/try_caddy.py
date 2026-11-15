"""Try what Caddy is told on a running Caddy: every answer of the two hosts carries the two headers, once each, and
Caddy writes no line about a request to its log.

Usage: python tools/try_caddy.py [--caddyfile FILE] [--pull] [--keep]

It starts the Caddy that deploy/compose.yaml pins, with Docker, on deploy/Caddyfile (or on FILE), and judges it
twice.

By what Caddy itself makes of the file (caddy adapt), which is asked first, of a Caddy that is given the file and no
network. Each of the two hosts, and each host's errors, pass the two lines that set the headers before anything can
answer. No other line sets or removes either header. No access log is on; the log leaves out what Caddy's errors and
its proxy write, where a request was found written; and it is written where it can be read here, above the debug
level. And the reading holds nothing that this tool has no rule for. Its rules are for what the stack's Caddyfile
becomes (a text, a file, a service the request is passed on to) and for what is known to change neither thing.
Anything else, a matcher that can write to the log, another way of speaking to a service, an option of the TLS
policy, is not known to hold, whatever Caddy answers to the requests below.

By what it does. With nothing behind it, and then with a stand-in for every service the file passes requests on to,
it is asked what a client asks and what one should not, and for every path that a path matcher of the file names.
The names of those services are held inside the run before Caddy is started, so that it looks for none outside.
Every answer has to carry the two headers once each, and Caddy may write nothing at all while it is asked.
Thirty of the requests are fixed: the cases of the security review, and one more at which Caddy's proxy writes an
error. They also hold the status, and some the body, that the stack answers with today, so that each is known to
have reached what it is there for.

The exit code is 0 when both hold: the digests for tests/test_deploy.py are then printed. It is 1 when an answer
does not carry the two headers as they must be, a line was written, or an access log is on. It is 2 when it could
not be tried, when Caddy's reading holds what this tool has no rule for, and when a case was not answered as the
stack answers today, though with both headers: the cases then have to be changed with the Caddyfile. Only 0 prints a
digest. Stopped by a signal, it ends in 130.

It needs Docker. Everything it starts is on this machine, published on the loopback alone, labelled cunho.try-caddy,
and removed when it ends (--keep leaves it, to look at). When Docker does not remove something, it says what, and
how to remove it by hand. It fetches no image unless --pull says so.

What it does not try. It speaks HTTP/1.1 to port 443, under two host names it makes up for the run, and no HTTP/2;
port 80, where Caddy only sends a client on to port 443, is not asked. What the server answers before it reaches a
host's own lines carries neither header and is not judged: a request it cannot read or will not take (400, 417, 431,
501, 505), `OPTIONS *`, a host name that is neither of the two. One of the two written with a dot at its end is such
a name to Caddy. Plain HTTP is sent to the TLS port once, for the log's sake, and its answer is not judged either.
Nor is the `100 Continue` that Caddy sends by itself. Of an answer, the headers that come before the body are
judged, not what a service sends after it. A path the file names is asked for as it is written: one that stands
inside a block that strips a prefix is not reached that way, and what holds for it is what Caddy's reading says.
Lines that Caddy can still write at its usual level are not provoked: for a TLS hello that offers nothing but the
ACME protocol (the sender's address, and no request), when a certificate is issued, and for a service that breaks
HTTP (for an answer with a status below 100 Caddy writes the visitor's address). Caddy is started on a file this
tool calls not known as well, to see what it answers, and the run's network has a way out. So a file that sends
Caddy somewhere by itself (to an issuer of certificates that it names, to another place for a check of a service's
health) is not kept from that. The stack's Caddyfile sends it nowhere but to its three services, whose names the run
holds. Of how Caddy is started it knows the caddy service of deploy/compose.yaml, with the block its logging
stands for: what another compose file given to Compose beside that one would change, it does not see.
research/cunho-security-review.md, section 10, says where the cases come from.
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import hashlib
import io
import json
import os
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import traceback
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import FrameType, TracebackType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CADDYFILE = "deploy/Caddyfile"
SERVICE = "the caddy service of deploy/compose.yaml"
WANTED = {"strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff"}
LEFT_OUT = {"http.log.error", "http.handlers.reverse_proxy"}  # the loggers of Caddy's errors and of its proxy
# The keys of a caddy service that this tool knows. It takes the image from it, gives Caddy the two host names, and
# puts the three things Caddy reads where the service mounts them. The other keys here change neither what Caddy
# reads nor what it answers: how the container is held, bounded and named. A service with any other key is
# refused. Some of those start Caddy on something that is not tried here (a command, an entrypoint, a file of
# more environment, one more mount); of the rest this tool does not know what they change.
KNOWN = {
    "image",
    "restart",
    "cap_drop",
    "cap_add",
    "security_opt",
    "read_only",
    "ports",
    "environment",
    "volumes",
    "networks",
    "logging",
    "depends_on",
    "mem_limit",
    "mem_reservation",
    "cpus",
    "pids_limit",
    "labels",
    "container_name",
    "stop_grace_period",
}
MOUNTS = [
    "- ./Caddyfile:/etc/caddy/Caddyfile:ro",
    "- ../demo/metadata/course/type_metadata:/srv/type_metadata:ro",
    "- public:/srv/public:ro",
    "- caddy-data:/data",
    "- caddy-config:/config",
]
GIVEN = ["ISSUER_HOST: ${ISSUER_HOST}", "DEMO_HOST: ${DEMO_HOST}"]  # the two names, as the service passes them
HARMLESS = {"vars"}  # cannot answer, and cannot touch a header of the answer: may come before the two lines
PATIENCE = 15.0  # how long an answer is waited for, in seconds
AWAY = (502, 503, 504)  # Caddy's own answers for a service it cannot reach
PASSED_ON = (("issuer", "/pid/tried"), ("issuer", "/course/tried"), ("demo", "/tried"))  # one path of each service
CRL = b"not a CRL: bytes for Caddy to serve, as the stack's first start publishes the real one\n"
SAID = {"ok": b"the service answered", "missing": b"the service has no such thing", "boom": b"the service failed"}
LONG = "A" * 33  # longer than Caddy takes for a method name: refused before a host's own lines are reached
LIMIT = 1 << 20  # of an answer, as much as is read: no case needs more than its head and a few bytes
LINGER = 2.0  # how long a client that leaves without an answer stays, in seconds
AS_IT_MUST = (  # what is said of a reading that is known to hold
    "the two headers' lines first for each host and its errors, and no other line for either of them",
    "no access log, and a log that leaves out Caddy's errors and its proxy and can be read here",
    "nothing in it that this tool has no rule for",
)
STOPS = tuple(getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name))

# The stand-in for a service: one answer for each connection. Which one, a header of the request says, so that no
# path a Caddyfile names can ask for the odd ones. Its own copies of the two headers are there to be replaced.
# busybox, which the Caddy image carries, runs it: nc -lk -p PORT -e sh.
HANDLER = r"""cr=$(printf '\r')
read -r method target version
kind=ok
while read -r line && [ "$line" != "$cr" ]; do
  case "$line" in
  X-Stand-In:*) kind=${line#X-Stand-In: } kind=${kind%"$cr"} ;;
  esac
done
own='Strict-Transport-Security: max-age=1\r\nX-Content-Type-Options: other\r\n'
answer() {
  printf "HTTP/1.1 %s\r\n${own}Content-Type: text/plain\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s" \
    "$1" "${#2}" "$2"
}
case "$kind" in
missing) answer "404 Not Found" "the service has no such thing" ;;
boom) answer "500 Internal Server Error" "the service failed" ;;
switch) printf 'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n' ;;
bare) printf 'HTTP/1.1 101 Switching Protocols\r\n\r\n' ;;
cut) printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1000000\r\n\r\nonly the start' ;;
stream)
  printf 'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n'
  while head -c 65536 /dev/zero; do sleep 0.2; done
  ;;
silent) sleep 20 ;;
*) answer "200 OK" "the service answered" ;;
esac
"""


class CannotTry(Exception):
    """What stands in the way of trying: no Docker, no image, a Caddy that does not start or does not answer in
    time, a file or a service written in a way this tool does not read."""


# What Caddy is told, as text. tests/test_deploy.py reads the two files with these, so that the digests printed
# here are the ones it holds.


def block(text: str, header: str, indent: str) -> str:
    """The lines under `header` that are indented deeper than it: one service or network of the compose file. A
    comment does not end it, wherever it starts: the lines after it still belong to what stands above. A line ends
    at a line feed, as it does for the readers of the file, and not at the other characters Python would end it at."""
    lines = text.split("\n")
    start = lines.index(f"{indent}{header}")
    body = []
    for line in lines[start + 1 :]:
        if line.strip() and not line.lstrip().startswith("#") and not line.startswith(indent + " "):
            break
        body.append(line)
    return "\n".join(body)


def said(text: str) -> str:
    """The lines of a file that say something: without its blank lines and without its comments, a comment being a
    line whose first character after spaces and tabs is a #. Caddy takes nothing from such a line and nothing from
    where it stands, as long as the file is plain (below)."""
    lines = (line for line in text.split("\n") if line.strip(" \t") and not line.lstrip(" \t").startswith("#"))
    return "".join(f"{line}\n" for line in lines)


def plain(caddyfile: str) -> str | None:
    """Why a Caddyfile is not plain, or None when it is. In a plain one every line stands by itself, so that what
    said() leaves of it is what Caddy reads. A backslash can join a line to the next one, or keep a quote from
    closing its text, and a text in quotes, in backquotes or after << can run over several lines: a line that looks
    like a comment is then a part of it, or a blank line ends what the line before began. A character that does
    not print can end a line for one reader and not for another. This tool does not read a line word by word, as
    Caddy does. So it takes no backslash, no backquote and no << at all, also where one would do no such thing,
    and a " only around one whole word. And before Caddy reads anything it fills in every {$NAME} of the file, in
    a comment as anywhere, from the {$ to the next } wherever that stands: a comment with a {$ in it could take
    the lines after it away. So a {$ stands in no comment, and ends on its own line."""
    odd = sorted({repr(char) for char in caddyfile if char not in "\t\n" and not char.isprintable()})
    if odd:
        return f"a character that does not print ({', '.join(odd)})"
    for line in caddyfile.split("\n"):
        if "{$" in line and line.lstrip(" \t").startswith("#"):
            return f"a {{$ in a comment, which Caddy fills in there as anywhere, up to the next }}: {line.strip()}"
        if "{$" in re.sub(r"\{\$[A-Za-z_][A-Za-z0-9_]*(:[^{}]*)?\}", "", line):
            return f"a {{$ that does not end on its line as {{$NAME}} or {{$NAME:default}} does: {line.strip()}"
    for line in said(caddyfile).split("\n"):
        if "\\" in line:
            return f"a backslash, and this tool takes none, since one can join a line to the next: {line.strip()}"
        if "`" in line or "<<" in line:
            return (
                f"a ` or a <<, and this tool takes neither, since either can open a text of many lines: {line.strip()}"
            )
        if '"' in re.sub(r'(?<![^ \t])"[^"]*"(?![^ \t])', "", line):
            return f'a " that is not around one whole word of one line: {line.strip()}'
    return None


def brought_in(caddyfile: str) -> str | None:
    """The line of an import that this tool does not follow, or None. It follows one kind: `import name` and no
    more, where the file itself opens a snippet of that name with `(name) {` at the start of a line. Another file
    is no part of what said() gives, and is not put where the Caddy of a run reads. A snippet's name is letters,
    digits, _ and -. Caddy takes `import name` for a file when it holds no snippet of that name, and it holds none
    for one that is opened inside another snippet, which this tool does not tell apart. A name that could be a
    path could then bring in a file. A plain one is looked for beside the Caddyfile, where no file is but the
    Caddyfile itself, and that one Caddy does not bring into itself: the import fails, in a run as in the stack.
    Words after the name are put into the snippet's lines, where one can become a line's first word: not followed."""
    own = set(re.findall(r"^\(([A-Za-z0-9_-]+)\)[ \t]+\{(?:[ \t]+#[^\n]*|[ \t]*)$", caddyfile, re.M))
    for line in said(caddyfile).split("\n"):
        words = line.split()
        if words and words[0].strip('"') == "import" and (len(words) != 2 or words[1] not in own):
            return line.strip()
    return None


ALIAS = r"    [A-Za-z0-9_-]+: \*([A-Za-z0-9_-]+)(?:[ \t]+#.*)?"  # a key of the caddy service whose value is an alias


def anchored(compose: str, name: str) -> list[str]:
    """The lines at the top of a compose file that give a block the name an alias stands for: `x-logging: &logging`."""
    return [line for line in compose.split("\n") if re.fullmatch(rf"[A-Za-z0-9_-]+: &{name}", line)]


def stood_for(compose: str) -> str:
    """What the caddy service takes by an alias from above the services. For each of its keys that says
    `key: *name`: the line at the top of the file that gives a block that name, and the lines of that block.
    misread() refuses a compose file in which an alias of the service is written otherwise, or does not stand
    for one such block."""
    held = ""
    for line in said(block(compose, "caddy:", "  ")).split("\n"):
        alias = re.fullmatch(ALIAS, line)
        for top in anchored(compose, alias.group(1)) if alias else []:
            held += f"{top}\n{said(block(compose, top, ''))}"
    return held


def told(caddyfile: str, compose: str) -> dict[str, str]:
    """What Caddy is told: what the Caddyfile says, and the service that starts Caddy on it, with what that
    service takes by an alias from above the services."""
    return {CADDYFILE: said(caddyfile), SERVICE: said(block(compose, "caddy:", "  ")) + stood_for(compose)}


def digests(caddyfile: str, compose: str) -> dict[str, str]:
    return {name: hashlib.sha256(text.encode()).hexdigest() for name, text in told(caddyfile, compose).items()}


def as_text(raw: bytes) -> str:
    """A file as it is, but for the line ends a Windows checkout gives it: Caddy ends a line at a line feed, and
    so does YAML. tests/test_deploy.py reads the two files with this, so that it and this tool read the same."""
    return raw.decode().replace("\r\n", "\n")


def caddyfile_text(path: Path) -> str:
    return as_text(path.read_bytes())


def key(line: str) -> str:
    """The name a line of the compose file gives its key, without the quotes and the spaces it may be written with."""
    return line.split(":")[0].strip(" \t\"'")


PLAIN = "_./=+-$"  # beside letters and digits, what a plain text inside brackets is made of


def left_open(line: str) -> tuple[bool, int | None]:
    """Whether a line of a compose file is left open at its end, inside a text in quotes or inside brackets that it
    does not close: YAML reads on from such a line into the next ones, wherever they begin. And, for a line that
    opens a block of text (a | or a > where a value begins), how far in the thing stands that the text belongs
    to: the lines of the text stand further in.

    A line is read as YAML's own scanner reads one that begins afresh, and with no less care: no line is called
    closed here that the scanner leaves open. A plain text outside brackets goes on to a colon and a blank, to a #
    after a blank or to the end of the line, and what it holds is a character of it: a quote, a bracket, a #.
    Everywhere else a quote opens a text and a bracket opens brackets, and a # begins a note, as it does for YAML
    right after a bracket, a comma or a text in quotes, with no blank before it: a bracket in that note closes
    nothing.

    A line is called open as well where it cannot be told: where the readers of YAML do not agree, or where what
    they make of the line is an error that only shows later. That is so inside brackets for a plain text with
    anything in it but letters, digits and a few signs (a ? ends such a text for one reader and not for another)
    and for a tag; for an anchor or an alias whose name is not plain, and a tag with a bracket, a comma or a quote
    in it; and anywhere for a text in quotes or in brackets that is followed by something else than a colon or,
    inside brackets, a comma or their end."""
    quote, depth, at = "", 0, 0
    word = whole = False  # inside a plain text; right after a text in quotes or in brackets, or an alias
    node = len(line) - len(line.lstrip(" "))  # until a key or a dash says otherwise, where the line itself begins
    while at < len(line):
        char, after = line[at], line[at + 1 : at + 2]
        apart = after in ("", " ", "\t")  # a blank comes next, or nothing does
        if quote:
            if char == quote == "'" and after == "'":
                at += 1  # two of them inside such a text are one of them, and do not end it
            elif char == quote:
                quote, whole = "", True
        elif char in " \t":
            pass
        elif char == "#" and not (word and line[at - 1] not in " \t"):
            break  # a note, to the end of the line: what is open stays open
        elif word and char == ":" and apart:
            word = False  # the colon after a key
        elif word and depth and char in ",[]{}":
            word = False
            continue  # the plain text ended before this character, which is read again as what it is
        elif word:
            if depth and not (char.isalnum() or char in PLAIN or (char == ":" and (after.isalnum() or after in PLAIN))):
                return True, None
        elif whole and not (char == ":" and (depth or apart)) and not (depth and char in ",]}"):
            return True, None
        elif char in "\"'":
            quote, node = char, (node if depth else at)
        elif char in "[{":
            depth, node = depth + 1, (node if depth else at)
        elif char in ",]}" and not depth:
            return True, None  # where a thing may begin outside brackets, it is an error for YAML
        elif char == ",":
            whole = False
        elif char in "]}":
            depth, whole = depth - 1, True
        elif char == ":" and (depth or apart):
            node, whole = (node if depth or whole else at), False  # with no key before it, it stands for the key
        elif (char in "-?" and apart and not depth) or (char == "?" and depth):
            node = node if depth else at
        elif char in "&*!":
            name = re.split(r"[ \t,\[\]{}]" if depth else r"[ \t]", line[at:], maxsplit=1)[0]
            if not re.fullmatch(r"[&*][A-Za-z0-9_-]+" if depth or char != "!" else r"[^,\[\]{}'\"]+", name):
                return True, None  # a name that one reader may end sooner than another, or a tag inside brackets
            node, whole = (node if depth else at), char == "*"  # what it stands before stands no less far in
            at += len(name) - 1
        elif char in "|>" and not depth:
            return False, node
        elif depth and not (char.isalnum() or char in PLAIN):
            return True, None
        else:
            word, node = True, (node if depth else at)  # a plain text begins
        at += 1
    return bool(quote) or depth != 0, None


def misread(compose: str) -> str | None:
    """Why the caddy service of a compose file cannot be taken as it is read here, line by line, or None when it
    can. The service is found by its line. So that line has to stand once, among the services, where no name comes
    twice however it is spelt, under a top level where no key comes twice and none holds a block of text: a copy of
    the service's lines inside such a block would be read in place of the service. No character may stand in the
    file that does not print: a reader that ends a line at one reads on from there what follows it. And no line
    may be left open at its end, by a quote or a bracket: YAML reads on from it wherever the next line begins, so
    that a line at the left ends the service for this tool and not for Compose, and what stands after it (a
    command) is hidden. A backslash is not taken either, since one keeps a quote from closing. Nor a second
    document. The lines of a block of text are text, and are not looked at.

    The caddy service itself holds no block of text, and a blank line stands there only between two of its keys.
    What is held of the service is its lines without the comments and the blank ones. Inside a text a line that
    begins with a # is text and no comment, and a blank line is a line break: neither would be held.

    And an alias stands in the caddy service only as the whole value of one of its keys (`logging: *logging`), for
    a block of its own at the top of the file that is given that name once and holds no alias, anchor or merge
    itself: the lines of that block are held with the service's, under the same two rules."""
    odd = sorted({repr(char) for char in compose if char not in "\t\n" and not char.isprintable()})
    if odd:
        return f"a character that does not print ({', '.join(odd)})"
    lines = compose.split("\n")
    text = None  # how far in the thing stands that a block of text belongs to, while the lines of that text go on
    texts: list[tuple[int, int]] = []  # where a block of text begins: the line's number, and how far in it stands
    for number, line in enumerate(lines, 1):
        bare, depth = line.strip(" \t"), len(line) - len(line.lstrip(" "))
        if text is not None and (not bare or depth > text):
            continue
        text = None
        if re.match(r"(---|\.\.\.)([ \t]|$)", line):
            return f"more than one document, or the end of one, at line {number}"
        if not bare.startswith("#"):
            if "\\" in line:
                return f"a backslash in line {number}"
            is_open, text = left_open(line)
            if is_open:
                return (
                    f"line {number} left open at its end, by a quote or a bracket, or written so that it cannot be told"
                )
            if text is not None:
                texts.append((number, depth))
    tops = [(number, key(line)) for number, line in enumerate(lines) if re.match(r"[^\s#-]", line)]
    names = [name for _, name in tops]
    if len(names) != len(set(names)):
        return "a key twice at its top"
    if [number for number, depth in texts if not depth]:
        return "a block of text at its top"
    if "services:" not in lines:
        return "no services where this tool looks for them"
    services = [key(line) for line in block(compose, "services:", "").split("\n") if re.match(r"  [^\s#-]", line)]
    if len(services) != len(set(services)) or [name for name in services if name.startswith("?")]:
        return "a service's name twice, or written as a question"
    if services.count("caddy") != 1 or lines.count("  caddy:") != 1:
        return "the caddy service not once and only once"
    first = lines.index("services:")
    last = min((number for number, _ in tops if number > first), default=len(lines))
    if not first < lines.index("  caddy:") < last:
        return "the caddy service elsewhere than among the services"
    own = block(compose, "caddy:", "  ")
    lost = not_held(own, lines.index("  caddy:") + 2, "    ", texts, "the caddy service")
    if lost:
        return lost
    for line in said(own).split("\n"):
        alias = re.fullmatch(ALIAS, line)
        if "*" in line and not alias:
            return f"a * in the caddy service that is no alias for the whole value of one of its keys: {line.strip()}"
        if alias:
            name, naming = alias.group(1), anchored(compose, alias.group(1))
            if len(naming) != 1 or len(re.findall(rf"&{name}(?![A-Za-z0-9_-])", said(compose))) != 1:
                return f"an alias in the caddy service, *{name}, that stands for no one block of its own at the top"
            theirs = block(compose, naming[0], "")
            if re.search(r"[*&]|<<", said(theirs)):
                return f"an alias, an anchor or a merge in the block that *{name} stands for"
            lost = not_held(theirs, lines.index(naming[0]) + 2, "  ", texts, f"the block that *{name} stands for")
            if lost:
                return lost
    return None


def not_held(own: str, begins: int, keys: str, texts: list[tuple[int, int]], where: str) -> str | None:
    """What of a block's lines would not be held when its comments and blank lines are left out, or None: a block
    of text in it, or a blank line that does not stand between two of its keys. `begins` is the number of its
    first line in the file, counted from 1; `keys` is how far in its own keys stand."""
    body = own.split("\n")
    if [number for number, _ in texts if begins <= number < begins + len(body)]:
        return f"a block of text in {where}, of whose lines a blank one or one that begins with a # is not held"
    blank = False
    for line in body:
        if not line.strip(" \t"):
            blank = True
        elif not line.lstrip(" \t").startswith("#"):
            if blank and not re.match(rf"{keys}\S", line):
                return f"a blank line in {where} elsewhere than between two of its keys"
            blank = False
    return None


def service(compose: str) -> str:
    """The image the compose file starts Caddy from, named by its digest. A service that this tool cannot start
    the same way, or that is not written the way it reads one, is refused, not tried by halves."""
    try:
        body = said(block(compose, "caddy:", "  "))
    except ValueError:
        raise CannotTry("the compose file has no caddy service where this tool looks for it") from None
    lines = body.split("\n")
    keys = [line.split(":")[0].strip() for line in lines if re.match(r"    \S", line)]
    unknown = sorted(set(keys) - KNOWN)
    if unknown:
        raise CannotTry(f"the caddy service has {', '.join(unknown)}, which this tool does not know how to try")
    twice = sorted({key for key in keys if keys.count(key) > 1})
    if twice:
        raise CannotTry(f"the caddy service has {', '.join(twice)} twice")
    image = re.search(r"^    image: (\S+?)(?::[^@/\s]+)?@(sha256:[0-9a-f]{64})$", body, re.M)
    if not image:
        raise CannotTry("the caddy service's image is not written as a name and a digest, the way this tool reads it")
    for key, known in (("volumes", MOUNTS), ("environment", GIVEN)):
        under = block(body, f"{key}:", "    ").split("\n") if f"    {key}:" in lines else []
        there = [line.strip() for line in under if line.strip()]
        if there != known:
            other = [line for line in there if line not in known] or [line for line in known if line not in there]
            raise CannotTry(
                f"the caddy service's {key} is not what this tool knows, or is not written the way it reads it: "
                f"{other[0] if other else 'the order of its lines'}"
            )
    return f"{image.group(1)}@{image.group(2)}"


# What Caddy makes of the Caddyfile: its own reading, as caddy adapt prints it.


def servers(config: Any) -> dict[str, Any]:
    """The HTTP servers in Caddy's reading: one, for a Caddyfile whose sites are all at port 443."""
    found = ((config.get("apps") or {}).get("http") or {}).get("servers")
    return found if isinstance(found, dict) else {}


def handlers(routes: Any) -> Iterator[dict[str, Any]]:
    """Every handler of some routes, however deep: those of a block's own routes, and those of the routes a proxy
    has for a service's answers."""
    for route in routes or []:
        for handler in route.get("handle") or []:
            yield handler
            yield from handlers(handler.get("routes"))
            for answer in handler.get("handle_response") or []:
                yield from handlers(answer.get("routes"))


def all_handlers(config: Any) -> Iterator[dict[str, Any]]:
    """Every handler of Caddy's reading: of each host's routes and of the routes for its errors."""
    for server in servers(config).values():
        yield from handlers(server.get("routes"))
        yield from handlers((server.get("errors") or {}).get("routes"))


def strange(node: Any, shape: Any, where: str) -> Iterator[str]:
    """Where a part of Caddy's reading holds what this tool has no rule for: a key that the shape does not name."""
    if callable(shape):
        yield from shape(node, where)
    elif isinstance(shape, list):
        for number, inner in enumerate(node):
            yield from strange(inner, shape[0], f"{where}[{number}]")
    elif isinstance(shape, dict):
        for name, inner in node.items():
            there = f"{where}.{name}" if where else name
            if name in shape or "*" in shape:
                yield from strange(inner, shape.get(name, shape.get("*")), there)
            else:
                yield there


def a_matcher(node: Any, where: str) -> Iterator[str]:
    yield from strange(node, {**dict.fromkeys(MATCHED_BY, ANY), "not": [a_matcher]}, where)


def a_route(node: Any, where: str) -> Iterator[str]:
    yield from strange(node, {"match": [a_matcher], "handle": [a_handler], "group": ANY, "terminal": ANY}, where)


def a_handler(node: Any, where: str) -> Iterator[str]:
    kind = node.get("handler")
    if kind in HANDLERS:
        yield from strange(node, {"handler": ANY, **HANDLERS[kind]}, where)
    else:
        yield f"{where} (the handler {kind})"


def a_status(node: Any, where: str) -> Iterator[str]:
    """A status has to be a fixed one, and one that an answer can have. One that a request fills in can be one
    Caddy cannot write: it then answers nothing, and writes a line of its own with the client's address."""
    if not re.fullmatch(r"[1-9][0-9]{2}", str(node)):
        yield f"{where} (a status that is not a fixed one)"


def a_text(node: Any, where: str) -> Iterator[str]:
    if not isinstance(node, str):
        yield f"{where} (a value that is no text)"


def plain_http(node: Any, where: str) -> Iterator[str]:
    if node != "http":
        yield f"{where} (a way of speaking to a service that is not plain HTTP)"


def of(*names: str) -> dict[str, Any]:
    return dict.fromkeys(names, ANY)


# What of Caddy's reading this tool has a rule for, by where it stands: the shape of what the stack's Caddyfile
# becomes, and beside it what is known to change nothing of the two things. Whatever else a reading holds, at any
# depth, is not known. It need not be harmful. But a matcher can write what a client sent to the log, a service
# can be spoken to in a way that writes every request there, a TLS policy can write to a file, and a handler of
# another kind may answer past the two lines. ANY is a part that is taken as it is.
#
# A `vars` line may give the place files are served from, as the stack's does, and nothing else. Caddy keeps what
# it knows of a request among those same names (whether it trusts the proxy in front, the client's address), and
# a line that puts something else under one of them makes Caddy's proxy fail on the request: no answer, and a
# line of Caddy's own with the client's address. A service's health has no rule: a Caddy that keeps count of a
# service's failures counts the ones these cases ask for, and answers for the service itself for a while. And a
# service may be spoken to in plain HTTP alone, with times of Caddy's own to give up at.
ANY = object()
MATCHED_BY = ("host", "path", "method", "header", "query")
HANDLERS: dict[str, dict[str, Any]] = {
    "subroute": {"routes": [a_route]},
    "headers": {"request": ANY, "response": of("set", "add", "delete", "replace", "require", "deferred")},
    "static_response": {"status_code": a_status, **of("body", "headers", "close", "abort")},
    "rewrite": of("uri", "method", "strip_path_prefix", "strip_path_suffix", "uri_substring", "path_regexp", "query"),
    "vars": {"root": a_text},
    "file_server": {"status_code": a_status, **of("hide", "root", "index_names", "pass_thru", "canonical_uris")},
    "reverse_proxy": {
        "upstreams": [of("dial")],
        "headers": of("request", "response"),
        "load_balancing": of("selection_policy", "retries", "try_duration", "try_interval"),
        "handle_response": [{"routes": [a_route], "status_code": a_status, "match": ANY}],
        "transport": {
            "protocol": plain_http,
            **of("dial_timeout", "response_header_timeout", "read_timeout", "write_timeout"),
            **of("expect_continue_timeout", "dial_fallback_delay"),
        },
        **of("flush_interval", "rewrite"),
    },
}
READING = {
    "admin": ANY,
    "logging": {"logs": {"*": of("writer", "encoder", "level", "include", "exclude")}},
    "apps": {
        "http": {
            "servers": {
                "*": {
                    "routes": [a_route],
                    "errors": {"routes": [a_route]},
                    "tls_connection_policies": [
                        of("match", "cipher_suites", "protocol_min", "protocol_max", "curves", "alpn")
                    ],
                    # Which proxies in front of Caddy are believed about a client's address (docs/DEMO.md).
                    "trusted_proxies": of("source", "ranges"),
                    **of("client_ip_headers", "trusted_proxies_strict"),
                    **of("listen", "logs", "protocols", "read_timeout", "read_header_timeout", "write_timeout"),
                    **of("idle_timeout", "max_header_bytes", "keepalive_interval"),
                }
            }
        }
    },
}


def takes(log: dict[str, Any], logger: str) -> bool:
    """Whether a log takes what a logger writes, by the names the log includes and the names it leaves out. Caddy
    goes by the longest of them that is the logger's own name or stands above it, and a log that includes some
    takes no other."""

    def longest(names: Any) -> int:
        return max((len(name) for name in names or [] if f"{logger}.".startswith(f"{name}.")), default=0)

    include, exclude = log.get("include"), log.get("exclude") or []
    if "*" in exclude:
        return False
    return longest(include) > longest(exclude) or not (include or longest(exclude))


def touches(handler: dict[str, Any]) -> bool:
    """Whether a headers handler sets, adds to, replaces or removes one of the two headers of an answer. A name
    may be written as a pattern, or be made up when a request comes: that one may be any name. So may a name with
    a letter that is no plain one, since Caddy and this tool do not make the same small letters of all of them."""
    response = handler.get("response") or {}
    patterns = [name for part in ("set", "add", "replace") for name in (response.get(part) or {})]
    patterns += list(response.get("delete") or [])
    return any(
        "{" in pattern or not pattern.isascii() or fnmatch.fnmatchcase(wanted, pattern.lower())
        for pattern in patterns
        for wanted in WANTED
    )


def sets(handler: dict[str, Any]) -> bool | None:
    """Which of the two lines of the Caddyfile's snippet a handler is, or None when it is neither. Such a line sets
    both headers, each once, whatever the answer is: one does it at once (False), the other as the answer is
    written (True). Beside that it may set, add to and remove other headers, by names that cannot be a name of one
    of the two (touches() says which can), and does nothing else to an answer. What it sets the two to is another
    matter, which amiss() tells."""
    response = handler.get("response") or {}
    given = response.get("set") or {}
    two = sorted(name.lower() for name in given if name.lower() in WANTED)
    if handler.get("handler") != "headers" or two != sorted(WANTED):
        return None
    others = {**response, "set": {name: value for name, value in given.items() if name.lower() not in WANTED}}
    if set(response) - {"set", "add", "delete", "deferred"} or touches({"response": others}):
        return None
    return bool(response.get("deferred"))


def amiss(handler: dict[str, Any]) -> list[str]:
    """Where a line of the snippet sets one of the two headers to something else than it must be."""
    given = {name.lower(): value for name, value in handler["response"]["set"].items()}
    wrong = [(name, given[name], value) for name, value in WANTED.items() if given[name] != [value]]
    return [
        f"a line sets {name} to {', '.join(map(str, is_set)) if isinstance(is_set, list) else is_set}, not to {value}"
        for name, is_set, value in wrong
    ]


def first(chain: Any) -> str:
    """What a chain of handlers does first: "set" when both lines of the snippet come before anything that can
    answer, "other" when something else comes before them, "harmless" when nothing in it can answer and nothing
    in it does anything to either header but what a line of the snippet does. A line that changes a header of the
    request is something else: Caddy finds a host's errors by the name the request carries then, and an error
    raised before the two lines has only that block to get the headers from."""
    seen = set()
    for handler in chain if isinstance(chain, list) else []:
        kind = handler.get("handler")
        if kind in HARMLESS or (kind == "headers" and not touches(handler) and "request" not in handler):
            continue
        if kind == "subroute" and begins(handler.get("routes")):
            return "set"
        if sets(handler) is None:
            return "other"
        seen.add(sets(handler))
        if len(seen) == 2:
            return "set"
    return "harmless"


def begins(routes: Any) -> bool:
    """Whether routes pass both lines of the snippet before anything in them can answer. Caddy goes through the
    routes in turn, and a line that sets a header holds for all that comes after it. A route that only some
    requests enter, or that shares a group with others (of a group, the first that matches is the only one
    entered), does not hold for all of them."""
    for route in routes if isinstance(routes, list) else []:
        state = first(route.get("handle"))
        if state == "set" and not {"match", "group"} & set(route):
            return True
        if state == "other" or (state == "harmless" and route.get("terminal")):
            return False
    return False


def unknown(config: Any, hosts: dict[str, str]) -> list[str]:
    """What in Caddy's reading of the Caddyfile is not what this tool knows to hold, each in a few words. `hosts`
    gives the two host names of the run."""
    found = {
        f"Caddy's reading holds {where}, for which this tool has no rule" for where in strange(config, READING, "")
    }
    if (config.get("admin") or {}).get("disabled") is not True:
        found.add("Caddy's own API is not off: what Caddy is told can then be changed while it runs")
    logs = (config.get("logging") or {}).get("logs") or {}
    for name, log in {"default": {}, **logs}.items():
        where = (log.get("writer") or {}).get("output", "stderr")
        if where == "discard":
            continue
        if where not in ("stderr", "stdout"):  # what docker keeps of the container is all that is read
            found.add(f"the log {name} is written where this run does not read it ({where})")
        if str(log.get("level", "")).upper() == "DEBUG":
            found.add(f"the log {name} is at the debug level, where Caddy names the client of a connection")
        kept = sorted(logger for logger in LEFT_OUT if takes(log, logger))
        if kept:
            found.add(f"the log {name} does not leave out {' and '.join(kept)}")
    names = {name: host for host, name in hosts.items()}
    for server in servers(config).values():
        if server.get("listen") != [":443"]:
            found.add(f"Caddy listens at {', '.join(server.get('listen') or []) or 'no address'}, not at 443 alone")
    for handler in all_handlers(config):
        lines = [handler] if handler.get("handler") == "headers" else []
        if handler.get("handler") == "reverse_proxy":  # what it does to the headers of a service's answer
            lines = [{"response": (handler.get("headers") or {}).get("response")}]
        if any(touches(line) and sets(line) is None for line in lines):
            found.add("another line sets or removes one of the two headers")
        if sets(handler) is not None:
            found.update(amiss(handler))
    for what, part in (("answers", "routes"), ("errors", "errors")):
        held: dict[str, list[bool]] = {host: [] for host in hosts}
        for server in servers(config).values():
            routes = server.get(part) if part == "routes" else (server.get(part) or {}).get("routes")
            for route in routes or []:
                match = route.get("match")
                alone = isinstance(match, list) and len(match) == 1 and set(match[0]) == {"host"}
                if not alone or not match[0]["host"] or not set(match[0]["host"]) <= set(names):
                    found.add(f"a site block that is not for the two hosts alone, among the {what}")
                    continue
                for name in match[0]["host"]:
                    held[names[name]].append(first(route.get("handle")) == "set")
        for host, each in held.items():
            if not each or not all(each):
                found.add(f"the {what} of the {host} host do not pass the two headers' lines before all else")
    return sorted(found)


def access_log(config: Any) -> bool:
    """Whether Caddy's own reading of the Caddyfile has an access log on, for any host and wherever it is written:
    a server has a part for its logs only then."""
    return any("logs" in server for server in servers(config).values())


def upstreams(config: Any) -> list[tuple[str, int]]:
    """The names and ports the Caddyfile passes requests on to, for the stand-in to answer at. This tool puts one
    at a name and a port, the name written as a compose file names a service, in small letters. It puts none at a
    socket, at an address, or at a name that is made up when a request comes. Nor where the service is looked up
    when a request comes, or spoken to in a way this tool has no rule for (anything but plain HTTP with times of
    its own): the stand-in might not be what answers, and what was asked of Caddy could leave the run."""
    found = set()
    for handler in all_handlers(config):
        if handler.get("handler") == "reverse_proxy":
            spoken_to = HANDLERS["reverse_proxy"]["transport"]
            others = ["dynamic_upstreams"] if "dynamic_upstreams" in handler else []
            others += ["transport"] if list(strange(handler.get("transport") or {}, spoken_to, "")) else []
            if others:
                raise CannotTry(
                    f"the Caddyfile passes requests on in a way this tool has no stand-in for ({others[0]})"
                )
            for upstream in handler.get("upstreams") or []:
                name, _, port = str(upstream.get("dial", "")).rpartition(":")
                named_so = re.fullmatch(r"[a-z0-9]([a-z0-9._-]*[a-z0-9])?", name) and not re.fullmatch(r"[0-9.]+", name)
                if not named_so or name == "localhost" or not port.isdigit() or not 0 < int(port) < 65536:
                    where = upstream.get("dial") or "a service it does not name by a name and a port"
                    raise CannotTry(f"the Caddyfile passes requests on to {where}, where this tool puts no stand-in")
                found.add((name, int(port)))
    return sorted(found)


def tries(config: Any) -> float:
    """How long Caddy goes on trying a service that is away before it answers, in seconds: the longest that its
    reading gives any of them."""
    kept = [handler.get("load_balancing") or {} for handler in all_handlers(config)]
    return max((float(balancing.get("try_duration") or 0) / 1e9 for balancing in kept), default=0.0)


def named(config: Any, hosts: dict[str, str]) -> list[Case]:
    """A request for every path that Caddy's reading names for one of the two hosts, with the methods named beside
    it, so that a route added later is asked as well. A path is asked for as it is written, a * in it filled in.
    One that cannot be asked for that way (it holds a placeholder, or a character an address does not take) is
    left out: what is known of its answers is what Caddy's reading says."""
    asked: set[tuple[str, str, str]] = set()
    names = {name: host for host, name in hosts.items()}

    def walk(routes: Any, host: str | None, methods: tuple[str, ...]) -> None:
        for route in routes or []:
            for matcher in route.get("match") or [{}]:
                for name in matcher.get("host") or [None]:
                    whose = names.get(name) if name is not None else host
                    how = tuple(matcher.get("method") or methods)
                    for path in matcher.get("path") or []:
                        target = path.replace("*", "tried")
                        target = target if target.startswith("/") else f"/{target}"
                        askable = re.fullmatch(r"[A-Za-z0-9/._~!$&'()+,;=:@%-]+", target) and not re.search(
                            r"%(?![0-9A-Fa-f]{2})", target
                        )
                        if whose is not None and askable:
                            asked.update(
                                (whose, method, target) for method in how if re.fullmatch(r"[A-Z]{1,32}", method)
                            )
                    for handler in route.get("handle") or []:
                        walk(handler.get("routes"), whose, how)
                        for answer in handler.get("handle_response") or []:
                            walk(answer.get("routes"), whose, how)

    for server in servers(config).values():
        walk(server.get("routes"), None, ("GET",))
        walk((server.get("errors") or {}).get("routes"), None, ("GET",))
    return [Case(host, method, path, 0, "a path the Caddyfile names") for host, method, path in sorted(asked)]


# The answers, and the judging of them.


@dataclass(frozen=True)
class Answer:
    status: int  # 0 when the connection was closed and nothing had come
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def values(self, name: str) -> list[str]:
        return [value for field, value in self.headers if field.lower() == name.lower()]


NOTHING = Answer(0, (), b"")


@dataclass(frozen=True)
class Case:
    """One thing asked of Caddy: of which host, how, and the answer that is right. A status of 0 is any status,
    and several are any of them: the two headers are what is looked for."""

    host: str
    method: str
    path: str
    status: int | tuple[int, ...]
    why: str
    allow: str | None = None
    body: bytes | None = None
    stand_in: str = "ok"  # which of its answers the stand-in is asked for
    leave: str | None = None  # the client goes: "reading", after the first bytes of the answer, or "waiting" for it


def alone(metadata: bytes) -> list[Case]:
    """With nothing behind Caddy: the two files it serves, its own 404s, and the errors it answers itself."""
    cases = []
    for host, path, content in (("issuer", "/crl/iaca.crl", CRL), ("demo", "/vct/course-certificate/1", metadata)):
        cases += [
            Case(host, "GET", path, 200, "a file Caddy serves", body=content),
            Case(host, "HEAD", path, 200, "the same, asked for by its head"),
            Case(host, "POST", path, 405, "the same, asked for with another method", allow="GET, HEAD"),
        ]
    cases += [
        Case("issuer", "GET", "/no-such-thing", 404, "a path no rule knows"),
        Case("issuer", "GET", "/pid/admin/offers", 404, "the operator API, which stays inside"),
        Case("issuer", "GET", "/pid/status/1", AWAY, "a service that is away"),
        Case("issuer", "GET", "/course/status/1", AWAY, "a service that is away"),
        Case("demo", "GET", "/", AWAY, "a service that is away"),
        Case("issuer", LONG, "/no-such-thing", 405, "a method name too long to be one"),
        Case("demo", LONG, "/", 405, "a method name too long to be one"),
    ]
    return cases


def passed_on() -> list[Case]:
    """A service's own answer, asked of each of the three services."""
    return [Case(host, "GET", path, 200, "a service's own answer", body=SAID["ok"]) for host, path in PASSED_ON]


def behind() -> list[Case]:
    """With a service behind Caddy: its own answers passed on, and the answers it breaks off or never gives."""
    cases = []
    for own in passed_on():
        host, path = own.host, own.path
        cases += [
            own,
            Case(host, "POST", path, 200, "the same, to a POST", body=SAID["ok"]),
            Case(host, "GET", path, 404, "a service's own 404", body=SAID["missing"], stand_in="missing"),
            Case(host, "GET", path, 500, "a service's own error", body=SAID["boom"], stand_in="boom"),
        ]
    host, path = PASSED_ON[0]
    cases += [
        Case(host, "GET", path, 200, "a service that switches protocols unasked", body=b"", stand_in="switch"),
        Case(host, "GET", path, 200, "the same, with no word of what it switches to", body=b"", stand_in="bare"),
        Case(host, "GET", path, 200, "an answer the service cuts short", stand_in="cut"),
        Case(host, "GET", path, 200, "an answer the client leaves half way", stand_in="stream", leave="reading"),
        Case(
            host, "GET", path, 0, "a client that leaves while the service is silent", stand_in="silent", leave="waiting"
        ),
    ]
    return cases


def dechunked(data: bytes) -> bytes:
    """The body of an answer that came in chunks: what the chunks hold, up to the chunk of no length that ends
    them, or to where the answer broke off."""
    out = b""
    while True:
        size, _, rest = data.partition(b"\r\n")
        length = int(size.split(b";")[0], 16) if re.fullmatch(rb"[0-9A-Fa-f]+(;.*)?", size) else 0
        if not length:
            return out
        out, data = out + rest[:length], rest[length + 2 :]


def parse(raw: bytes) -> Answer | None:
    """The answer in what came back, or None when no whole head did. An interim answer (100, 103) is followed by
    the one that counts."""
    while True:
        head, end, raw = raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        start = re.match(r"HTTP/\d\.\d (\d{3})", lines[0])
        if not start or not end:
            return None
        status = int(start.group(1))
        if not (status in (100, 102, 103) and raw.startswith(b"HTTP/")):
            break
    pairs = (line.partition(":") for line in lines[1:])
    headers = tuple((name.strip(), value.strip()) for name, colon, value in pairs if colon)
    answer = Answer(status, headers, raw)
    chunked = any("chunked" in value.lower() for value in answer.values("transfer-encoding"))
    return Answer(status, headers, dechunked(raw)) if chunked else answer


def faults(case: Case, answer: Answer | None) -> tuple[list[str], list[str]]:
    """What is wrong with the answer to a case, of two kinds. First, where it does not carry the two headers once
    each, as they must be: that is what does not hold. Then, where it is not the answer this case expects of the
    stack (another status, another body, no answer at all): the two headers may be right all the same, and the
    case no longer fits the Caddyfile. A connection closed with nothing sent is no answer: it is of the second
    kind, and only where an answer was expected."""
    if case.leave == "waiting":
        return [], []  # no answer was waited for: the case is there for what Caddy writes about it
    if answer is None:
        return [], ["an answer that cannot be read"]
    right = (case.status,) if isinstance(case.status, int) else case.status
    if not answer.status:
        return [], ([] if right == (0,) else ["no answer: the connection was closed"])
    bare, other = [], []
    for name, value in WANTED.items():
        values = answer.values(name)
        if len(values) != 1:
            bare.append(f"{name} {len(values)} times")
        elif values[0] != value:
            bare.append(f"{name} says {values[0]}")
    if right != (0,) and answer.status not in right:
        other.append(f"answered {answer.status}, not {' or '.join(map(str, right))}")
    if case.allow is not None and answer.values("allow") != [case.allow]:
        other.append(f"Allow says {', '.join(answer.values('allow')) or 'nothing'}")
    if case.body is not None and answer.body != case.body:
        other.append(f"a body of {len(answer.body)} bytes that is not the one expected")
    return bare, other


def written(before: tuple[list[str], list[str]], after: tuple[list[str], list[str]]) -> list[str]:
    """The lines of a log that were not there before, of both of its streams. A log that no longer begins with
    what was there before is not the log that was read."""
    streams = ((before[0], after[0]), (before[1], after[1]))
    if any(now[: len(was)] != was for was, now in streams):
        raise CannotTry("Caddy's log could not be read: it no longer holds what it held before Caddy was asked")
    return [line for was, now in streams for line in now[len(was) :]]


# The Caddy that is tried, and what stands around it.


def last(said: bytes, most: int) -> str:
    """The end of what a command or a container said, as text: as much as a message can carry."""
    return said.decode(errors="replace")[-most:]


@contextlib.contextmanager
def held_back() -> Iterator[None]:
    """While a command is being started, a signal to end is held back until the command is there to be ended with
    it. Taken a moment earlier, it would leave a command behind that nobody waits for and nobody stops."""
    if not hasattr(signal, "pthread_sigmask"):
        yield
        return
    before = signal.pthread_sigmask(signal.SIG_BLOCK, STOPS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


def docker(
    *args: str, data: bytes | None = None, check: bool = True, wait: float = 120
) -> subprocess.CompletedProcess[bytes]:
    """One docker command, in a session of its own: a Ctrl-C at the terminal goes to this tool, which ends the
    command itself or goes on with it, and not to the command behind the tool's back."""
    given = subprocess.DEVNULL if data is None else subprocess.PIPE
    process = None
    try:
        with held_back():
            process = subprocess.Popen(
                ["docker", *args], stdin=given, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
            )
        out, err = process.communicate(data, timeout=wait)
    except FileNotFoundError:
        raise CannotTry("Docker is needed, and there is no docker command here") from None
    except BaseException as reason:
        if process is not None:  # it is ended with whatever ended the wait for it
            process.kill()
            process.communicate()
        if isinstance(reason, subprocess.TimeoutExpired):
            raise CannotTry(f"docker {args[0]} did not come back within {wait:.0f} seconds") from None
        if isinstance(reason, OSError):  # no room for one more process, a docker that may not be run
            raise CannotTry(f"docker {args[0]} could not be run: {reason}") from None
        raise
    if check and process.returncode:
        raise CannotTry(f"docker {' '.join(args[:2])}: {last(err, 400).strip()}")
    return subprocess.CompletedProcess(args, process.returncode, out, err)


def flushed() -> None:
    """What was printed is out, before something is said on the other stream. It may be that nobody reads it, or
    that there is nowhere to print to: that is no reason to end otherwise than the run ended."""
    with contextlib.suppress(AttributeError, OSError, ValueError):
        sys.stdout.flush()


def let_go(stream: Any) -> None:
    """From here on, what is written to a stream goes nowhere. It is for a stream that cannot be written to any
    more: Python writes out what is left of its two as the process ends, and ends it in 120 when that fails."""
    with contextlib.suppress(AttributeError, OSError, ValueError):
        os.dup2(os.open(os.devnull, os.O_WRONLY), stream.fileno())


def warned(why: str) -> None:
    """Say on standard error what a run could not do. Where that cannot be written, nobody is told, and that is
    all: an error raised over it would end the process in 1, which is how "It does not hold" ends."""
    try:
        sys.stderr.write(f"{why}\n")
        sys.stderr.flush()
    except (AttributeError, ValueError):  # started with no standard error, or with a closed one
        pass
    except OSError:
        let_go(sys.stderr)


def ended(code: int, why: str) -> int:
    """How a run ends that reached no verdict: what it printed is written out, why it ended is said after that,
    and its code is the one given. What it printed is let go when nobody reads it any more."""
    try:
        sys.stdout.flush()
    except (AttributeError, ValueError):
        pass
    except OSError:
        let_go(sys.stdout)
    warned(why)
    return code


def archive(files: dict[str, bytes]) -> bytes:
    """A tar of files by their path in a container, which docker cp takes on its standard input."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path, content in files.items():
            entry = tarfile.TarInfo(path.strip("/"))
            entry.size, entry.mode = len(content), 0o644
            tar.addfile(entry, io.BytesIO(content))
    return buffer.getvalue()


def unchecked() -> ssl.SSLContext:
    """TLS without a look at the certificate: Caddy signs for the run's two names with an authority it makes for
    itself. HTTP/1.1 is all that is offered."""
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    return context


def connected(port: int, name: str, wait: float) -> ssl.SSLSocket:
    """A connection to the Caddy of a run, with the TLS handshake done under a host name."""
    plain_socket = socket.create_connection(("127.0.0.1", port), timeout=wait)
    try:
        return unchecked().wrap_socket(plain_socket, server_hostname=name)
    except OSError:
        plain_socket.close()
        raise


def greeted(port: int, name: str) -> bool:
    """Whether Caddy completes a TLS handshake under a name: it does once it has made the name's certificate."""
    try:
        connected(port, name, 5).close()
    except OSError:
        return False
    return True


def ask(port: int, name: str, case: Case, wait: float = PATIENCE) -> Answer | None:
    """One request to the Caddy of a run, under the host name `name`, and what came back: an answer, NOTHING when
    the connection was closed with nothing sent, None when what came is no answer. No more than LIMIT bytes are
    read and no longer than `wait` seconds: an answer whose head has not come by then is not waited for. A Caddy
    that takes no connection, or does not complete the handshake, cannot be asked at all."""
    asked = f"{case.method[:12]} {case.path} of the {case.host} host"
    head = f"{case.method} {case.path} HTTP/1.1\r\nHost: {name}\r\nX-Stand-In: {case.stand_in}\r\n"
    head += "Connection: close\r\n\r\n"
    data, end = b"", time.monotonic() + wait
    try:
        tls = connected(port, name, wait)
    except OSError as reason:
        raise CannotTry(f"Caddy took no connection for {asked} ({reason}): it may have stopped") from None
    with tls:
        try:
            tls.sendall(head.encode())
            if case.leave == "waiting":
                time.sleep(LINGER)
                return NOTHING
            while len(data) < LIMIT:
                left = end - time.monotonic()
                if left <= 0:
                    raise TimeoutError
                tls.settimeout(left)
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
                if case.leave == "reading" and b"\r\n\r\n" in data:
                    break
        except TimeoutError:
            if b"\r\n\r\n" not in data:
                raise CannotTry(f"Caddy gave no answer to {asked} within {wait:.0f} seconds") from None
        except OSError:
            pass  # an answer that was broken off is judged by what did come
    return parse(data) if data else NOTHING


def poke(port: int) -> bytes:
    """A client that speaks no TLS, at the port where Caddy expects it, and what came back to it. Nothing is
    judged of that: a Caddy that writes about every connection writes about this one."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as plain_socket:
            plain_socket.sendall(b"GET / HTTP/1.1\r\nHost: nobody\r\n\r\n")
            return plain_socket.recv(4096)
    except OSError:
        return b""


@contextlib.contextmanager
def undisturbed() -> Iterator[None]:
    """While what a run started is removed, a second Ctrl-C or a signal to end is not heard: half of it would
    stay behind."""
    before = {number: signal.signal(number, signal.SIG_IGN) for number in STOPS}
    try:
        yield
    finally:
        for number, handler in before.items():
            signal.signal(number, handler)


class Rig:
    """One Caddy on one Caddyfile, on a network of its own, with or without a service behind it. Its two hosts
    get names made for the run, so that no Caddyfile can have named them."""

    def __init__(self, image: str, files: dict[str, bytes], keep: bool = False) -> None:
        self.image, self.files, self.keep = image, files, keep
        tag = secrets.token_hex(4)
        self.name = f"try-caddy-{tag}"
        self.hosts = {"issuer": f"issuer-{tag}.localhost", "demo": f"demo-{tag}.localhost"}
        self.caddy, self.stand_in, self.reader = (f"{self.name}-{part}" for part in ("caddy", "service", "reading"))
        self.label = ("--label", f"cunho.try-caddy={self.name}")
        self.named = ("-e", f"ISSUER_HOST={self.hosts['issuer']}", "-e", f"DEMO_HOST={self.hosts['demo']}")
        self.proof = f"{self.name}: a line that try_caddy.py wrote, to see that this log is read"
        self.started: list[str] = []
        self.port: int  # the one Docker publishes Caddy at, known once Caddy is started

    def __enter__(self) -> Rig:
        """The network of the run, with nothing in it yet. Caddy is started once what it will look for is there."""
        try:
            docker("network", "create", *self.label, self.name)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        self.started.append(f"the network {self.name}")
        return self

    def start(self) -> None:
        """Start the Caddy of the run on its files, and wait until it greets under both names."""
        # Its log is kept where docker logs reads it, whatever this Docker keeps logs in by itself.
        how = ("--network", self.name, "-p", "127.0.0.1::443", "--log-driver", "json-file", *self.label, *self.named)
        docker("create", "--name", self.caddy, *how, self.image)
        self.started.append(f"the container {self.caddy}")
        docker("cp", "-", f"{self.caddy}:/", data=archive(self.files))
        docker("start", self.caddy)
        published = docker("port", self.caddy, "443/tcp", check=False).stdout.decode().split()
        if not published:  # it has stopped already: something in the Caddyfile that it cannot do
            raise CannotTry(f"Caddy did not start. It wrote:\n{self.said_by(self.caddy)}")
        self.port = int(published[0].rpartition(":")[2])
        self.until_it_greets()

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None, trace: TracebackType | None
    ) -> None:
        if self.keep:
            if self.started:
                print(f"left as it is: {', '.join(self.started)}", flush=True)
            return
        stayed = []
        with undisturbed():
            for remove in (
                ("rm", "-f", "-v", self.reader),
                ("rm", "-f", "-v", self.caddy),
                ("rm", "-f", "-v", self.stand_in),
                ("network", "rm", self.name),
            ):
                try:
                    done = docker(*remove, check=False, wait=30)
                except Exception:  # whatever kept this one from being removed, the next is tried all the same
                    stayed.append(remove)
                    continue
                never_there = rb"No such container: |network \S+ not found"  # which is gone as well
                if done.returncode and not re.search(never_there, done.stderr):
                    stayed.append(remove)
        if stayed:
            by_hand = "; ".join(f"docker {' '.join(remove)}" for remove in stayed)
            flushed()
            warned(f"Docker did not remove all that this run started. By hand: {by_hand}")

    def ask(self, case: Case) -> Answer | None:
        return ask(self.port, self.hosts[case.host], case)

    def until_it_greets(self) -> None:
        """Wait until Caddy completes a TLS handshake under both names. A Caddy that has stopped did not take the
        Caddyfile; one that runs and greets nobody within a minute cannot be tried."""
        end = time.monotonic() + 60
        waiting = list(self.hosts.values())
        while waiting and time.monotonic() < end:
            if greeted(self.port, waiting[0]):
                waiting.pop(0)
                continue
            if not self.runs():
                raise CannotTry(f"Caddy did not start. It wrote:\n{self.said_by(self.caddy)}")
            time.sleep(0.3)
        if waiting:
            wrote = self.said_by(self.caddy)
            raise CannotTry(f"Caddy runs, and completed no TLS handshake within a minute. It wrote:\n{wrote}")

    def runs(self) -> bool:
        """Whether the Caddy of the run still runs."""
        return docker("inspect", "-f", "{{.State.Running}}", self.caddy, check=False).stdout.strip() == b"true"

    def adapted(self) -> Any:
        """What Caddy makes of the Caddyfile, as it prints it. It is asked of a Caddy of the same image that is
        given the file where the stack mounts it and the two names, starts no server and has no network. So the
        reading is known before the Caddy of the run is started, and that one finds every name it will look for
        already held."""
        read = "cat > /etc/caddy/Caddyfile && exec caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile"
        how = ("--rm", "-i", "--network", "none", "--name", self.reader, *self.label, *self.named)
        given = self.files["etc/caddy/Caddyfile"]
        made = docker("run", *how, "--entrypoint", "sh", self.image, "-c", read, data=given, check=False)
        if made.returncode:
            raise CannotTry(f"Caddy does not take the Caddyfile. It wrote:\n{last(made.stderr, 1500)}")
        try:
            config = json.loads(made.stdout)
        except ValueError:
            config = None
        if not isinstance(config, dict):
            raise CannotTry("what Caddy made of the Caddyfile could not be read")
        return config

    def hold_the_names(self, where: list[tuple[str, int]]) -> None:
        """Put a container of this run under every name the Caddyfile passes requests on to, with nothing in it
        that listens yet, before Caddy is started. What Caddy finds there is a service that is away. And it looks
        for none of those names outside the run, where something might answer and be sent what is asked of Caddy."""
        names = [part for name in sorted({name for name, _ in where}) for part in ("--network-alias", name)]
        ports = " ".join(str(port) for port in sorted({port for _, port in where}))
        how = ("--network", self.name, *names, *self.label, "-e", f"HANDLER={HANDLER}", "-e", f"PORTS={ports}")
        docker("run", "-d", "--name", self.stand_in, *how, "--entrypoint", "sh", self.image, "-c", "tail -f /dev/null")
        self.started.append(f"the container {self.stand_in}")

    def put_a_service_behind(self, where: list[tuple[str, int]]) -> None:
        """Start the stand-in in the container that holds the names, at every port the Caddyfile passes requests
        on to. Wait until Caddy's own container reaches it at each, and until Caddy passes a request on to it."""
        start = (
            'printf "%s" "$HANDLER" > /tmp/handler.sh; '
            'for port in $PORTS; do nc -lk -p "$port" -e sh /tmp/handler.sh & done; wait'
        )
        docker("exec", "-d", self.stand_in, "sh", "-c", start)
        end = time.monotonic() + 30
        for name, port in where:
            reach = ("exec", self.caddy, "wget", "-q", "-O", "-", "-T", "2", f"http://{name}:{port}/")
            while docker(*reach, check=False).stdout != SAID["ok"]:
                if not self.runs():  # it is asked from beside Caddy: a Caddy that is gone is not the stand-in's fault
                    raise CannotTry(f"Caddy has stopped. It wrote:\n{self.said_by(self.caddy)}")
                if time.monotonic() > end:
                    raise CannotTry(
                        f"the stand-in service did not answer at {name}:{port}. It wrote:\n"
                        f"{self.said_by(self.stand_in)}"
                    )
                time.sleep(0.3)
        for own in passed_on():  # a Caddy that checks a service's health takes a while to pass requests on
            while time.monotonic() < end:
                answer = self.ask(own)
                if answer is None or answer.status not in AWAY:
                    break
                time.sleep(0.5)

    def said_by(self, container: str) -> str:
        """The end of what a container wrote, for a message, whatever docker says of being asked for it: the
        message is about something else, and is not to be lost for it."""
        try:
            done = docker("logs", container, check=False)
        except CannotTry as reason:
            return f"(not to be had: {reason})"
        return last(done.stdout + done.stderr, 1500)

    def log(self) -> tuple[list[str], list[str]]:
        """What Caddy has written so far, line by line, to each of its two streams."""
        done = docker("logs", self.caddy, check=False)
        if done.returncode:
            raise CannotTry(f"Caddy's log could not be read: {last(done.stderr, 400).strip()}")
        out, err = (
            [line for line in stream.decode(errors="replace").split("\n") if line.strip()]
            for stream in (done.stdout, done.stderr)
        )
        return out, err

    def quiet_log(self) -> tuple[list[str], list[str]]:
        """Caddy's log once it has stopped growing, so that what Caddy writes about its own start is not held
        against it. A line is written to it first, beside Caddy and the way Caddy writes one: a log in which that
        line does not show is no log to judge by, whatever Docker says of it."""
        docker("exec", self.caddy, "sh", "-c", f'echo "{self.proof}" > /proc/1/fd/2')
        lines = self.log()
        for _ in range(20):
            time.sleep(1)
            again = self.log()
            if again == lines and self.proof in again[1]:
                return again
            lines = again
        if self.proof not in lines[1]:
            raise CannotTry("Caddy's log could not be read: a line this run wrote to it does not show in it")
        raise CannotTry("Caddy goes on writing to its log while nothing is asked of it")


def run(rig: Rig, cases: list[Case]) -> tuple[int, int]:
    """Ask the cases and print a line for each. Count those whose answer does not carry the two headers as they
    must be (NO), and those that carry them but are not the answer the case expects of the stack (??)."""
    lost = off = 0
    width = max(len(case.path) for case in cases)
    for case in cases:
        answer = rig.ask(case)
        bare, other = faults(case, answer)
        lost, off = lost + bool(bare), off + bool(other)
        mark = "NO" if bare else "??" if other else "ok"
        method = case.method if len(case.method) <= 8 else f"{case.method[:3]}...({len(case.method)})"
        status = str(answer.status) if answer is not None and answer.status else "   "
        print(f"  {mark:<3} {method:<10} {case.host:<7}{case.path:<{width}} {status}  {case.why}")
        for fault in bare + other:
            print(f"      {fault}")
    return lost, off


def count(number: int, one: str, more: str) -> str:
    return f"{number} {one if number == 1 else more}"


def tried(caddyfile: Path, pull: bool, keep: bool) -> int:
    type_metadata = ROOT / "demo" / "metadata" / "course" / "type_metadata" / "course-certificate-1.json"
    try:
        composed, as_it_is = (ROOT / "deploy" / "compose.yaml").read_bytes(), caddyfile.read_bytes()
        metadata = type_metadata.read_bytes()
    except OSError as reason:
        raise CannotTry(f"a file it needs could not be read: {reason}") from None
    for name, raw in (("deploy/compose.yaml", composed), (str(caddyfile), as_it_is)):
        try:
            raw.decode()
        except UnicodeDecodeError as reason:
            raise CannotTry(f"{name} is not text: {reason}") from None
    # The file is read once: what is looked at here, what the digest is of and what Caddy is given are one reading,
    # also where a second one would give something else (a pipe).
    compose, text = as_text(composed), as_text(as_it_is)
    if misread(compose) is not None:
        raise CannotTry(f"the compose file has {misread(compose)}: its caddy service cannot be taken as it reads here")
    image = service(compose)
    if plain(text) is not None:
        raise CannotTry(f"the Caddyfile has {plain(text)}. It is read line by line here, and has to be plain")
    if brought_in(text) is not None:
        raise CannotTry(
            f"the Caddyfile has an import this tool does not follow ({brought_in(text)}). It follows `import name` "
            "and no more, for a snippet the file itself opens with `(name) {`"
        )
    answering = docker("version", check=False)
    if answering.returncode:
        raise CannotTry(f"Docker does not answer: {last(answering.stderr, 400).strip()}")
    looked = docker("image", "inspect", image, check=False)
    if looked.returncode:
        if b"No such image" not in looked.stderr:
            raise CannotTry(f"docker image inspect: {last(looked.stderr, 400).strip()}")
        if not pull:
            raise CannotTry(f"the image {image} is not on this machine: --pull fetches it")
        docker("pull", image, wait=540)
    files = {
        "etc/caddy/Caddyfile": as_it_is,
        "srv/public/iaca.crl": CRL,
        "srv/type_metadata/course-certificate-1.json": metadata,
    }
    with Rig(image, files, keep) as rig:
        print(f"Caddy {image}\non {caddyfile}\nas {rig.hosts['issuer']} and {rig.hosts['demo']}\n", flush=True)
        config = rig.adapted()
        try:
            if any("h1" not in server.get("protocols", ["h1"]) for server in servers(config).values()):
                raise CannotTry(
                    "the Caddyfile leaves HTTP/1.1 out of what Caddy speaks, and this tool speaks nothing else"
                )
            not_known, logged = unknown(config, rig.hosts), access_log(config)
            print("what Caddy makes of the file")
            if logged:
                print("  NO  an access log is on")
            for what in not_known:
                print(f"  ??  {what}")
            if not logged and not not_known:
                print("".join(f"  ok  {what}\n" for what in AS_IT_MUST), end="")
            every_path, where, tried_for = named(config, rig.hosts), upstreams(config), tries(config)
        except (AttributeError, TypeError, KeyError, ValueError, RecursionError):  # a list where a name stands
            raise CannotTry("what Caddy made of the Caddyfile is not of the shape this tool reads") from None
        if tried_for > PATIENCE - 2:
            raise CannotTry(
                f"the Caddyfile has Caddy go on trying a service that is away for {tried_for:.0f} seconds "
                f"(try_duration): too long for this tool, which waits {PATIENCE:.0f} for an answer"
            )
        if where:
            rig.hold_the_names(where)
        rig.start()
        before = rig.quiet_log()
        print("nothing behind Caddy", flush=True)
        lost, off = run(rig, alone(metadata) + every_path)
        if where:
            rig.put_a_service_behind(where)
        print("a service behind Caddy", flush=True)
        more = run(rig, behind() + every_path)
        lost, off = lost + more[0], off + more[1]
        poke(rig.port)
        time.sleep(1.5)  # for what Caddy writes about the last of it
        lines = written(before, rig.log())
    print(f"\nCaddy's log: {count(len(lines), 'line', 'lines') if lines else 'nothing'} written while it was asked")
    for line in lines[:12]:
        print(f"  {line[:500]}")
    if logged or lost or lines:
        parts = ["an access log is on"] if logged else []
        parts += [f"{count(lost, 'answer does', 'answers do')} not carry the two headers as they must"] if lost else []
        parts += [f"Caddy wrote {count(len(lines), 'line', 'lines')} while it was asked"] if lines else []
        print(f"\nIt does not hold: {', and '.join(parts)}.")
        return 1
    if off or not_known:
        print("\nIt is not known to hold. No answer lacked a header and Caddy wrote nothing while it was asked, but:")
        if off:
            unmet = (
                f"  {count(off, 'case was', 'cases were')} not answered as this tool expects of the stack (?? above)"
            )
            print(f"{unmet}." if not_known else f"{unmet}:")
        if not not_known:
            print("  its cases no longer fit the Caddyfile, and have to be changed with it before it can vouch for it.")
        if not_known:
            print(f"  Caddy reads the file in a way this tool does not know: {'; '.join(not_known)}.")
        return 2
    print("\nIt holds: Caddy reads the file as it must, every answer carries the two headers once each, and Caddy")
    print("wrote nothing while it was asked.")
    print("What was tried, for TRIED in tests/test_deploy.py:")
    for name, digest in digests(text, compose).items():
        print(f'    "{name}": "{digest}",')
    if caddyfile.resolve() != (ROOT / CADDYFILE).resolve():
        print(f"The first is the digest of {caddyfile}, which is not {CADDYFILE}.")
    return 0


def stopped(number: int, frame: FrameType | None) -> None:
    raise KeyboardInterrupt  # so that what was started is removed, as after Ctrl-C


def main() -> int:
    parser = argparse.ArgumentParser(description=str(__doc__).split("\n\n")[0])
    parser.add_argument("--caddyfile", type=Path, default=ROOT / "deploy" / "Caddyfile", help="another file to try")
    parser.add_argument("--pull", action="store_true", help="fetch the image when it is not on this machine")
    parser.add_argument("--keep", action="store_true", help="leave the containers and the network, to look at")
    args = parser.parse_args()
    # A signal to end is taken as Ctrl-C is. One that this was started to ignore stays ignored: a hangup under
    # nohup, a Ctrl-C at the terminal for what a script put in the background.
    minded = [number for number in STOPS if signal.getsignal(number) != signal.SIG_IGN]
    before = {number: signal.signal(number, stopped) for number in minded}
    try:
        code = tried(args.caddyfile, args.pull, args.keep)
        with contextlib.suppress(AttributeError, ValueError):  # nowhere to print to is no reason to end otherwise
            sys.stdout.flush()  # here, so that a reader that has gone is found out before the run is called ended
        return code
    except CannotTry as reason:
        return ended(2, f"It could not be tried: {reason}")
    except KeyboardInterrupt:
        return ended(130, "It was stopped before its end, and nothing is known from it.")
    except BrokenPipeError:  # whoever read what this prints has gone: there is nobody to give a verdict to
        return ended(2, "It could not be tried to its end: nobody reads what it prints any more.")
    except Exception:  # a fault of this tool is no verdict: it must not end as "It does not hold" does
        fault = f"{traceback.format_exc()}It could not be tried: this tool went wrong, as shown above."
        return ended(2, f"{fault} Nothing is known from it.")
    finally:
        for number, handler in before.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
