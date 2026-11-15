"""The page's static files: served with the security headers, nothing inline or from another origin, and every word
in both languages."""

from __future__ import annotations

import re
from pathlib import Path

from cunho_demo.offers import CARD
from cunho_demo.texts import LABELS, TEXT

from .conftest import Demo

STATIC = Path(__file__).resolve().parents[2] / "src" / "cunho_demo" / "static"


def dictionary(language: str) -> set[str]:
    """The keys of one language in i18n.js."""
    source = (STATIC / "i18n.js").read_text()
    start = source.index(f"  {language}: {{")
    end = source.index("\n  },", start)
    return set(re.findall(r"^    ([a-z_0-9]+):", source[start:end], re.MULTILINE))


def test_the_page_is_served_with_its_files(demo: Demo) -> None:
    page = demo.client.get("/")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-cache"
    assets = ("/styles.css", "/fonts.css", "/app.js", "/card.js", "/i18n.js", "/favicon.svg", "/arms.svg")
    for asset in (*assets, "/fonts/SpaceGrotesk.ttf"):
        answer = demo.client.get(asset)
        assert answer.status_code == 200, asset
        assert answer.headers["cache-control"] == "no-cache", "a page never runs with a file from another release"


def test_nothing_inline_and_nothing_from_elsewhere() -> None:
    page = (STATIC / "index.html").read_text()
    scripts = re.findall(r"<script([^>]*)>", page)
    assert scripts and all(re.search(r'src="/[a-z0-9]+\.js"', attributes) for attributes in scripts)
    assert not re.search(r"\son[a-z]+=", page), "no inline event handlers"
    assert not re.search(r'(src|href)="(https?:)?//', page), "nothing loaded from another origin"
    assert "style=" not in page
    styles = (STATIC / "styles.css").read_text()
    assert "@import" not in styles and "url(" not in styles
    # the one stylesheet with a url() names the card's typeface, served by the demo itself
    fonts = (STATIC / "fonts.css").read_text()
    assert "@import" not in fonts and re.findall(r"url\(([^)]*)\)", fonts) == ['"/fonts/SpaceGrotesk.ttf"']
    assert (STATIC / "fonts" / "OFL.txt").read_text().startswith("Copyright 2020 The Space Grotesk Project Authors")
    arms = (STATIC / "arms.svg").read_text()
    assert "<script" not in arms and not re.search(r"\son[a-z]+=", arms) and "http://www.w3.org" in arms
    assert not re.search(r'(xlink:)?href="(https?:)?//', arms), "the arms name nothing outside themselves"


def test_every_word_of_the_page_in_both_languages() -> None:
    english, portuguese = dictionary("en"), dictionary("pt")
    assert english == portuguese
    page = (STATIC / "index.html").read_text()
    used = set(re.findall(r'data-i18n="([a-z_0-9]+)"', page))
    script = (STATIC / "app.js").read_text()
    used |= set(re.findall(r'\bt\("([a-z_0-9]+)"', script))
    used |= {f"status_{s}" for s in re.findall(r"^    ([a-z_]+): \[", script, re.MULTILINE)}
    used |= {f"ended_{s}" for s in ("refused", "failed", "deleted", "revoked", "closed", "expired")}
    assert used <= english, sorted(used - english)


def test_every_word_of_the_screens_in_both_languages() -> None:
    assert set(TEXT["en"]) == set(TEXT["pt"])
    assert set(LABELS["en"]) == set(LABELS["pt"])


def test_every_field_on_a_card_has_its_label_in_both_languages() -> None:
    """app.js names the label of each field on a card's face as claim_<name>, which the other checks cannot see."""
    for language in ("en", "pt"):
        words = dictionary(language)
        for credential, names in CARD.items():
            assert {f"claim_{name}" for name in names} <= words, (language, credential)


def test_the_first_action_shows_the_code_and_the_card_says_it_is_a_demo() -> None:
    """Try it now makes the offer and shows its QR code: the demo wallet runs only when the visitor asks for it. The
    card with the country's arms says it is not an official document, on its face and next to the button."""
    page = (STATIC / "index.html").read_text()
    assert 'class="button primary" id="start" data-i18n="start"' in page
    assert 'data-i18n="demo_only"' in page
    script = (STATIC / "app.js").read_text()
    end = script.index("// What both pages show once they have an offer")
    start = script[script.index("async function start(") : end]
    assert "demo-wallet" not in start, "making an offer never starts the demo wallet by itself"
    assert 't("card_demo_corner")' in script and 't("card_demo_corner_course")' in script
    styles = (STATIC / "styles.css").read_text()
    assert "body.simple .scan" not in styles, "Simple shows the switch to the wallet app's code too"
    for language in ("en", "pt"):
        words = dictionary(language)
        assert {"start", "demo_only", "card_demo_corner", "status_stored_demo", "stored_note"} <= words
