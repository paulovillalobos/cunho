"""The demo stack's files (deploy/), held to what the security review of the live deployment found, so a later edit
cannot quietly undo it. The files are read as text: nothing here starts a container. What a container alone can
show, what Caddy answers and writes to its log, tools/try_caddy.py tries."""

from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


def tool(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"{name}_for_the_deploy_tests", ROOT / "tools" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # its dataclasses look their module up by name
    spec.loader.exec_module(module)
    return module


# The tool reads the two files, and these tests read them with it: block() gives the lines of a service, said() the
# lines of a file that say something, and the digests it prints after a run are the ones held in TRIED below.
TRY = tool("try_caddy")
block, said = TRY.block, TRY.said
COMPOSE = TRY.as_text((DEPLOY / "compose.yaml").read_bytes())
CADDYFILE = TRY.caddyfile_text(DEPLOY / "Caddyfile")
DOCKERFILE = (DEPLOY / "Dockerfile").read_text()
LOCK = DEPLOY / "requirements.txt"


def site(host: str) -> str:
    """One site block of the Caddyfile, from its address to the closing brace in the first column."""
    found = re.search(rf"^\{{\${host}\}} \{{\n(.*?)^\}}", CADDYFILE, re.M | re.S)
    assert found, f"no site block for {host}"
    return found.group(1)


# What Caddy is told, as it was tried: the sha256 of what the Caddyfile says and of the service that starts Caddy on
# it. test_caddy_is_told_what_was_tried_and_nothing_else says what to do when one of them changes.
TRIED = {
    "deploy/Caddyfile": "8fc32a155ba7b7acfe3d274ec0240836c959c914b8e2e786178bfe53145bf998",
    "the caddy service of deploy/compose.yaml": "4400c8fe8ddf47ad74776d8a26b0c55ceb6c1b91dd144a8d2765c744503e98c6",
}


def test_the_outside_network_carries_ipv6() -> None:
    """Without IPv6 on the network Caddy is published from, Docker's userland proxy hands every IPv6 connection on
    from the bridge's own IPv4 address: all IPv6 visitors then count as one client for every rate limit and for the
    console's wrong-password lockout."""
    assert re.search(r"^\s+enable_ipv6: true$", block(COMPOSE, "edge:", "  "), re.M)
    assert "enable_ipv6" not in block(COMPOSE, "internal:", "  ")  # no route out, in either family
    assert re.search(r"^\s+internal: true$", block(COMPOSE, "internal:", "  "), re.M)


def test_only_caddy_is_published_and_on_the_outside_network() -> None:
    services = ("init", "cunho-pid", "cunho-course", "demo", "caddy")
    for name in services:
        body = block(COMPOSE, f"{name}:", "  ")
        outside = "ports:" in body or re.search(r"networks: \[[^\]]*edge", body) is not None
        assert outside == (name == "caddy"), name
    assert "network_mode: none" in block(COMPOSE, "init:", "  ")


def test_every_image_is_pinned_by_digest() -> None:
    bases = re.findall(r"^FROM (\S+)", DOCKERFILE, re.M)
    images = [i for i in re.findall(r"^\s+image: (\S+)", COMPOSE, re.M) if i != "cunho-demo:local"]
    assert bases and images
    for image in bases + images:
        assert re.fullmatch(r"[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}", image), image


def test_the_image_takes_only_locked_dependencies() -> None:
    """Every Python package of the image is the version and the file the lock names: a release made after the lock
    cannot enter a build, and a download that differs from the locked one stops it."""
    installs = [line for line in DOCKERFILE.splitlines() if "pip " in line and not line.lstrip().startswith("#")]
    assert installs
    for line in installs:
        assert "--require-hashes" in line and "--only-binary" in line and "requirements.txt" in line, line
    entries = re.split(r"\n(?=[A-Za-z0-9])", LOCK.read_text())
    entries = [e for e in entries if e.strip() and not e.startswith("#")]
    pinned = {}
    for entry in entries:
        name, version = re.match(r"([A-Za-z0-9._-]+)==(\S+)", entry).groups()  # type: ignore[union-attr]
        assert "--hash=sha256:" in entry, name
        pinned[re.sub(r"[-_.]+", "-", name).lower()] = version
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    wanted = project["dependencies"] + project["optional-dependencies"]["pkcs11"]
    wanted += project["optional-dependencies"]["demo"]
    for requirement in wanted:
        name = re.sub(r"[-_.]+", "-", re.match(r"[A-Za-z0-9._-]+", requirement).group(0)).lower()  # type: ignore[union-attr]
        assert name in pinned, f"{name} is a dependency the lock does not pin"


def test_caddy_sets_the_headers_on_what_it_answers_itself() -> None:
    """The applications set their own headers; the files Caddy serves and its own 404s had none. Both hosts take
    the one snippet. It sets them twice: at once, so that an answer Caddy writes later without passing through
    these lines again has them (its error for a file asked for with another method or for a service that is away
    went out with neither), and as the response is written, so that an application's own copy is replaced."""
    snippet = re.search(r"^\(headers\) \{\n(.*?)^\}", CADDYFILE, re.M | re.S)
    assert snippet
    two = '\t\tStrict-Transport-Security "max-age=31536000"\n\t\tX-Content-Type-Options "nosniff"\n'
    assert said(snippet.group(1)) == f"\theader {{\n{two}\t}}\n\theader {{\n{two}\t\tdefer\n\t}}\n"
    for host in ("ISSUER_HOST", "DEMO_HOST"):
        assert re.search(r"^\timport headers$", site(host), re.M), host


def test_caddy_sets_the_headers_on_the_errors_it_answers_too() -> None:
    """What Caddy refuses before it reaches a host's own lines (a method name too long to be one) is an error
    that the snippet's lines never saw. Each host hands its errors to a block that sets the headers again."""
    for host in ("ISSUER_HOST", "DEMO_HOST"):
        assert "\thandle_errors {\n\t\timport headers\n\t}\n" in said(site(host)), host


def test_caddy_writes_no_line_about_a_request() -> None:
    """Without an access log Caddy still wrote the client's address, the address it asked for and its headers when
    a request could not be passed on, and when an answer was cut short. The two loggers that do so are left out
    of the log."""
    options = re.search(r"\A.*?^\{\n(.*?)^\}", CADDYFILE, re.M | re.S)
    assert options
    assert "\tlog {\n\t\texclude http.log.error http.handlers.reverse_proxy\n\t}\n" in said(options.group(1))


def test_caddy_is_told_what_was_tried_and_nothing_else() -> None:
    """What Caddy answers and what it writes to its log cannot be read off its configuration by a test that starts
    nothing. A line that takes a header away again, an option inside the servers block that turns the access log
    on, a second block for a host, the debug level, an import moved under another line: each undoes one of the
    three tests above, and each has passed tests that looked for the right words in the right place. So what Caddy
    is told is held as a whole: what the Caddyfile says, and the service that starts Caddy on it, image and
    environment included, are the ones that were tried on a running Caddy, where every answer of both hosts carried
    the two headers and no line about a request was written (research/cunho-security-review.md, section 10, has
    the cases). A change to either is tried again the same way before its digest is put here: tools/try_caddy.py
    does that, and prints the digests when everything holds."""
    # What the Caddyfile says is taken line by line, here and by the tool, without its comments and blank lines. A
    # line that goes on in the next one, a quoted text that runs over several lines, a file brought in from
    # elsewhere or a character that does not print would let the same lines say something else to Caddy. So would
    # a {$ in a comment: Caddy fills it in there as anywhere, up to the next } wherever that stands. The Caddyfile
    # has none of them.
    assert TRY.plain(CADDYFILE) is None, f"deploy/Caddyfile has {TRY.plain(CADDYFILE)}"
    followed = "deploy/Caddyfile has an import the tool does not follow"
    assert TRY.brought_in(CADDYFILE) is None, f"{followed}: {TRY.brought_in(CADDYFILE)}"
    # The service held below is the one the compose file starts. It is found by its line, so that line stands once,
    # among the services, where no name comes twice however it is spelt, under a top level where no key comes twice
    # and none holds a block of text, in a file of one document with no character that does not print and no line
    # left open at its end by a quote or a bracket, which YAML would read on from wherever the next line begins.
    # And the service itself holds no block of text and no blank line but between two of its keys: of a text's
    # lines, a blank one or one that begins with a # would not be held below. The tool refuses a compose file that
    # is otherwise, and says why. What the service takes by an alias from above the services (its logging) is held
    # with its own lines: an alias stands there only as the whole value of a key, for one block at the top.
    assert TRY.misread(COMPOSE) is None, f"deploy/compose.yaml has {TRY.misread(COMPOSE)}"
    assert TRY.digests(CADDYFILE, COMPOSE).keys() == TRIED.keys()
    for name, digest in TRY.digests(CADDYFILE, COMPOSE).items():
        assert digest == TRIED[name], (
            f"{name} no longer says what was tried on a running Caddy: "
            "python tools/try_caddy.py tries it, and prints the digest to put here when everything holds"
        )


def test_caddy_offers_only_what_the_stack_serves_and_ends_slow_requests() -> None:
    """The compose file publishes TCP only, so HTTP/3 is not offered; a request's headers and body must arrive
    within a set time, so connections held open with a trickle of bytes are closed."""
    options = re.search(r"\A.*?^\{\n(.*?)^\}", CADDYFILE, re.M | re.S)
    assert options
    assert "admin off" in options.group(1)
    assert re.search(r"protocols h1 h2$", options.group(1), re.M)
    for name in ("read_header", "read_body", "idle"):
        assert re.search(rf"^\s+{name} \d+[sm]$", options.group(1), re.M), name


def test_the_operator_api_is_refused_before_anything_is_proxied() -> None:
    body = site("ISSUER_HOST")
    assert "@admin path /pid/admin /pid/admin/* /course/admin /course/admin/*" in body
    refused = body.index("handle @admin {\n\t\trespond 404")
    for upstream in ("cunho-pid", "cunho-course"):
        assert refused < body.index(f"reverse_proxy {upstream}:8000"), upstream
    # A pattern with a % in it is matched against the path as it was sent, not as it decodes.
    assert "%" not in body.split("@admin path", 1)[1].split("\n", 1)[0]


def test_what_a_service_prints_is_kept_within_a_bound() -> None:
    """Docker keeps a container's output without limit unless told otherwise: one error that anyone can repeat
    would fill the disk in time."""
    limits = block(COMPOSE, "x-logging: &logging", "")
    size, files = re.search(r"^\s+max-size: (\d+)m$", limits, re.M), re.search(r'^\s+max-file: "(\d+)"$', limits, re.M)
    assert size and files
    assert int(size.group(1)) * int(files.group(1)) == 30, "docs/DEMO.md says 30 MB of what each service prints"
    assert "logging: *logging" in block(COMPOSE, "x-hardened: &hardened", "")
    assert "logging: *logging" in block(COMPOSE, "caddy:", "  ")
    assert "<<: *hardened" in block(COMPOSE, "x-cunho: &cunho", "")
    assert "<<: *hardened" in block(COMPOSE, "demo:", "  ")
    for name in ("cunho-pid", "cunho-course"):
        assert "<<: *cunho" in block(COMPOSE, f"{name}:", "  "), name


def test_an_image_build_sees_only_what_it_copies() -> None:
    """The image runs cunho from the sources it copies, so whatever lies beside them on the machine that builds it
    would be in the image too, compiled files included, which Python runs in preference to a source they match."""
    rules = [line for line in (ROOT / ".dockerignore").read_text().splitlines() if line and not line.startswith("#")]
    assert rules[0] == "*", "everything is left out unless a later line lets it in"
    allowed = [line[1:] for line in rules if line.startswith("!")]
    for dockerfile in (DOCKERFILE, (ROOT / "tools" / "oidf" / "Dockerfile").read_text()):
        copied = [s for line in re.findall(r"^COPY (?!--)(.+) \S+$", dockerfile, re.M) for s in line.split()]
        assert copied
        for source in copied:
            assert any(source == entry or source.startswith(f"{entry}/") for entry in allowed), source
    # The last rule that matches decides: these come after every line that lets something in.
    last_allowed = max(index for index, line in enumerate(rules) if line.startswith("!"))
    for left_out in ("**/__pycache__", "**/*.py[cod]"):
        assert rules.index(left_out) > last_allowed, left_out
