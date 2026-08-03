"""unicode_reveal — vendored, self-contained detection + neutralization logic.

Educational visualizer for a KNOWN evasion class: hidden / invisible Unicode,
homoglyph confusables, and Turkish dotless-i casefold traps in text destined
for an LLM prompt. No novelty is claimed here.

Prior art credited:
  - NVIDIA garak PR #1997 (Turkish casefold buff) — the casefold-trap idea.
  - Unicode UTS #39 "Unicode Security Mechanisms" (confusables / restriction).
  - Unicode UTS #55 & the Bidi (UAX #9) trojan-source literature.

Maps to OWASP LLM Top 10 (LLM01: Prompt Injection) and MITRE ATLAS
(AML.T0051 LLM Prompt Injection). This is defensive testing tooling: it
reveals and strips evasion, it does not author attacks.

Pure standard library. No network, no third-party imports — so a Hugging Face
Space importing it stays self-contained and the functions stay unit-testable
without Gradio installed.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------- #
# Character class definitions
# --------------------------------------------------------------------------- #

# Zero-width and other invisible format characters commonly abused to smuggle
# instructions past a human reviewer while remaining in the byte stream.
ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x061C: "ARABIC LETTER MARK",
}

# Bidirectional control characters — the "Trojan Source" (CVE-2021-42574) class.
BIDI_CONTROLS = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
}

# Unicode Tag block (U+E0000..U+E007F). ASCII can be mirrored invisibly here;
# heavily used to hide instructions inside text or emoji sequences.
TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

# Variation selectors — another modern invisible-payload smuggling channel.
VARIATION_SELECTORS = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))

# A compact, high-signal homoglyph map: confusable code points -> ASCII skeleton.
# Sourced from the spirit of UTS #39 confusables (a small curated subset, not
# the full data file). Keys are the "look-alike", values the intended ASCII.
HOMOGLYPHS = {
    # Cyrillic look-alikes
    "а": "a",  # CYRILLIC SMALL LETTER A
    "е": "e",  # CYRILLIC SMALL LETTER IE
    "о": "o",  # CYRILLIC SMALL LETTER O
    "р": "p",  # CYRILLIC SMALL LETTER ER
    "с": "c",  # CYRILLIC SMALL LETTER ES
    "у": "y",  # CYRILLIC SMALL LETTER U
    "х": "x",  # CYRILLIC SMALL LETTER HA
    "і": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "ԁ": "d",  # CYRILLIC SMALL LETTER KOMI DE
    "ԛ": "q",  # CYRILLIC SMALL LETTER QA
    "ѕ": "s",  # CYRILLIC SMALL LETTER DZE
    "ѳ": "o",  # CYRILLIC SMALL LETTER FITA
    # Greek look-alikes
    "ο": "o",  # GREEK SMALL LETTER OMICRON
    "α": "a",  # GREEK SMALL LETTER ALPHA
    "ε": "e",  # GREEK SMALL LETTER EPSILON
    "ρ": "p",  # GREEK SMALL LETTER RHO
    "υ": "u",  # GREEK SMALL LETTER UPSILON
    "ι": "i",  # GREEK SMALL LETTER IOTA
    "Ι": "I",  # GREEK CAPITAL LETTER IOTA
    "Ο": "O",  # GREEK CAPITAL LETTER OMICRON
    # Fullwidth Latin (U+FF21..FF5A) handled programmatically below.
}


# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    """One flagged character (or short span) in the input."""

    offset: int          # character index into the ORIGINAL string
    byte_offset: int     # UTF-8 byte offset into the original string
    char: str            # the actual character
    codepoint: int       # U+XXXX value
    category: str        # zero-width | bidi | tag-block | variation-selector |
                         # homoglyph | casefold-trap
    name: str            # human-readable Unicode name
    note: str = ""       # extra context (e.g. homoglyph target)

    @property
    def u(self) -> str:
        return f"U+{self.codepoint:04X}"


@dataclass
class RevealResult:
    original: str
    cleaned: str
    findings: list = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return bool(self.findings)

    def counts(self) -> dict:
        out: dict = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _char_name(ch: str) -> str:
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "UNNAMED / PRIVATE-USE"


def _is_fullwidth_latin(cp: int) -> bool:
    # Fullwidth ASCII variants U+FF01..U+FF5E map to U+0021..U+007E.
    return 0xFF01 <= cp <= 0xFF5E


def _fullwidth_to_ascii(cp: int) -> str:
    return chr(cp - 0xFEE0)


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

def scan(text: str) -> list:
    """Return a list of Findings for every suspicious code point in *text*.

    Byte offsets are computed against the original UTF-8 encoding so a reviewer
    can locate the character in a raw payload.
    """
    findings: list = []
    byte_offset = 0
    for i, ch in enumerate(text):
        cp = ord(ch)
        cat: Optional[str] = None
        note = ""

        if cp in ZERO_WIDTH:
            cat = "zero-width"
        elif cp in BIDI_CONTROLS:
            cat = "bidi"
        elif TAG_BLOCK_START <= cp <= TAG_BLOCK_END:
            cat = "tag-block"
            # Tag characters mirror ASCII at cp - 0xE0000.
            mirrored = cp - TAG_BLOCK_START
            if 0x20 <= mirrored <= 0x7E:
                note = f"mirrors ASCII {chr(mirrored)!r}"
        elif cp in VARIATION_SELECTORS:
            cat = "variation-selector"
        elif ch in HOMOGLYPHS:
            cat = "homoglyph"
            note = f"looks like {HOMOGLYPHS[ch]!r}"
        elif _is_fullwidth_latin(cp):
            cat = "homoglyph"
            note = f"fullwidth -> {_fullwidth_to_ascii(cp)!r}"
        elif ch in ("ı", "İ", "̇"):
            # Turkish dotless-i family: casefold traps (see garak #1997).
            # ı (U+0131) LATIN SMALL LETTER DOTLESS I
            # İ (U+0130) LATIN CAPITAL LETTER I WITH DOT ABOVE
            # ̇ (U+0307) COMBINING DOT ABOVE
            cat = "casefold-trap"
            note = _casefold_note(ch)

        if cat is not None:
            findings.append(
                Finding(
                    offset=i,
                    byte_offset=byte_offset,
                    char=ch,
                    codepoint=cp,
                    category=cat,
                    name=_char_name(ch),
                    note=note,
                )
            )

        byte_offset += len(ch.encode("utf-8"))

    return findings


def _casefold_note(ch: str) -> str:
    folded = ch.casefold()
    lowered = ch.lower()
    detail = (
        f"casefold={folded!r} vs lower={lowered!r}"
        if folded != lowered
        else f"folds to {folded!r}"
    )
    return (
        "Turkish dotless-i: naive .lower()/.upper() can turn a guard word into "
        f"a non-match ({detail})"
    )


# --------------------------------------------------------------------------- #
# Neutralization / canonicalization
# --------------------------------------------------------------------------- #

def neutralize(text: str) -> str:
    """Return a defanged copy of *text*.

    Strategy (order matters):
      1. Drop invisible format chars (zero-width, bidi, tag block, var-selectors).
      2. Map curated homoglyphs + fullwidth Latin back to their ASCII skeleton.
      3. NFKC-normalize to collapse remaining compatibility variants.

    This mirrors the "prompt-canon" style canonicalization: make the string
    look to a filter the way it looks to a human. It is deliberately lossy for
    invisible content — that is the point.
    """
    out_chars: list = []
    for ch in text:
        cp = ord(ch)
        if (
            cp in ZERO_WIDTH
            or cp in BIDI_CONTROLS
            or (TAG_BLOCK_START <= cp <= TAG_BLOCK_END)
            or cp in VARIATION_SELECTORS
        ):
            continue  # strip invisibles
        if ch in HOMOGLYPHS:
            out_chars.append(HOMOGLYPHS[ch])
            continue
        if _is_fullwidth_latin(cp):
            out_chars.append(_fullwidth_to_ascii(cp))
            continue
        out_chars.append(ch)

    stripped = "".join(out_chars)
    # NFKC folds leftover compatibility forms (ligatures, circled letters, ...).
    return unicodedata.normalize("NFKC", stripped)


def reveal(text: str) -> RevealResult:
    """One-call convenience: scan + neutralize."""
    return RevealResult(
        original=text,
        cleaned=neutralize(text),
        findings=scan(text),
    )
