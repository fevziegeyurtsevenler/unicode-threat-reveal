---
title: Unicode Threat Reveal
emoji: 🔍
colorFrom: indigo
colorTo: red
sdk: static
pinned: false
license: apache-2.0
tags:
  - security
  - prompt-injection
  - unicode
---

# unicode-threat-reveal — reveal invisible unicode & detect hidden characters in text

**unicode-threat-reveal is a zero width character detector and hidden-Unicode
visualizer for prompt-injection review.** Paste any text and it will *reveal
invisible unicode* — zero-width joiners, bidirectional controls, the Unicode
tag block, variation selectors, homoglyph look-alikes, and Turkish dotless-i
casefold traps — highlighted in place, listed in a findings table with
codepoints and byte offsets, and returned as a neutralized, prompt-safe copy.

If you need to **detect hidden characters in text** before it reaches an LLM,
a moderation filter, a code review, or a search index, this tool makes the
invisible visible.

Maps to **OWASP LLM Top 10 — LLM01: Prompt Injection** and **MITRE ATLAS —
AML.T0051 (LLM Prompt Injection)**. This is authorized, defensive
security-testing tooling.

## What it detects

| Class | Examples | Why it matters |
|-------|----------|----------------|
| Zero-width / invisible format | `U+200B` ZWSP, `U+200D` ZWJ, `U+FEFF` BOM, `U+00AD` soft hyphen | Hidden instructions smuggled between visible letters |
| Bidirectional controls | `U+202E` RLO, `U+2066` LRI (Trojan Source, CVE-2021-42574) | Display order differs from stored order |
| Unicode tag block | `U+E0000`–`U+E007F` | Invisibly mirrors ASCII; hides text inside emoji/strings |
| Variation selectors | `U+FE00`–`U+FE0F`, `U+E0100`+ | Modern invisible-payload channel |
| Homoglyph confusables | Cyrillic `а е о`, Greek `ο α`, fullwidth `Ｉｇｎ` | `іgnоrе` looks like `ignore` but isn't |
| Turkish dotless-i casefold | `ı` (U+0131), `İ` (U+0130) | Naive `.lower()`/`.upper()` breaks guard-word matching |

## How it works

1. **Scan** — every code point is checked against curated sets of invisible,
   bidi, tag-block, variation-selector, homoglyph, and casefold-trap
   characters. Each hit records its Unicode name, `U+XXXX` codepoint, character
   index, and UTF-8 byte offset.
2. **Reveal** — invisible characters are rendered as visible `U+XXXX`
   placeholders and confusables are badged, so a human reviewer can see exactly
   what a machine would ingest.
3. **Neutralize** — invisibles are stripped, homoglyphs and fullwidth Latin are
   folded to their ASCII skeleton, then the string is `NFKC`-normalized. The
   result is a canonical copy that looks to a filter the way it looks to a
   human.

The detection and normalization logic is a small, dependency-free,
standard-library-only module (`unicode_reveal.py`) vendored directly into this
Space so it stays self-contained and unit-testable without Gradio installed.

## Use it in your own pipeline: `prompt-canon`

This Space is the visual front-end. The same *canonicalize-before-you-guard*
normalization ships as a maintained, dependency-free Python library you can drop
straight into your own guardrail or moderation pipeline:

```bash
pip install prompt-canon
```

- PyPI: https://pypi.org/project/prompt-canon/
- Source: https://github.com/fevziegeyurtsevenler/prompt-canon

Paste-and-see here; `import prompt_canon` in production.

## Run locally

```bash
pip install -r requirements.txt
python app.py
```

## Run the tests

The core logic runs on the Python standard library alone — no Gradio needed:

```bash
python -m unittest discover -s tests -v
```

## Static bookmarklet (no server)

`static/index.html` performs the same reveal entirely client-side, and
`bookmarklet.md` provides a paste-and-run bookmarklet — "paste this, watch the
hidden instruction appear." Nothing is uploaded; all analysis is local to your
browser.

## Honesty & prior art

This is an **educational visualizer of a known evasion class**. It claims **no
novelty**. It stands on:

- **NVIDIA garak** [PR #1997](https://github.com/NVIDIA/garak/pull/1997) — the
  Turkish casefold buff, source of the dotless-i trap idea.
- **Unicode UTS #39**, *Unicode Security Mechanisms* — the confusables /
  restriction-level framework behind homoglyph detection.
- **UAX #9** (Bidi) and the **Trojan Source** work (CVE-2021-42574) — the
  bidirectional-control class.
- **Unicode UTS #55** — source-code spoofing guidance.

Related, more comprehensive tools exist, including `confusable_homoglyphs`,
`unicodedata`/`unidecode`, `ftfy`, and garak's own buffs. This project is a
focused, transparent visualizer, not a replacement for a full confusables
database or a normalization library.

### Limits

- The homoglyph map is a **curated high-signal subset**, not the full UTS #39
  confusables data — some look-alikes will not be flagged.
- Neutralization is deliberately **lossy** for invisible content (that is the
  point) and may alter legitimate text (e.g. intentional ZWJ in emoji, or
  meaningful bidi in mixed-script content). Review before use.
- A clean result is **not a safety guarantee** — it means none of the *checked*
  classes were present, not that the text is safe.

## Responsible use

This tool reveals and strips evasion; it does not author attacks. The example
payloads are benign demonstrations. Use it to defend systems you are authorized
to test. Do not use it to craft or refine adversarial input against systems you
do not own or have permission to assess.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

## İlgili AltaySec Kaynakları

- 📖 [Sıfır Genişlikli Unicode ile Gizli Talimat: SKILL.md Tedarik Zinciri Saldırısı](https://altaysec.com.tr/arastirmalar/sifir-genislikli-unicode-gizli-talimat) — konunun derinlemesine Türkçe analizi
- 🌐 [AltaySec Araştırmalar](https://altaysec.com.tr/arastirmalar/) — Türkçe yapay zekâ güvenliği yazıları

## Atıf

```bibtex
@software{altaysec_unicode_threat_reveal_2026,
  author = {{AltaySec}},
  title  = {unicode-threat-reveal},
  year   = {2026},
  url    = {https://github.com/fevziegeyurtsevenler/unicode-threat-reveal}
}
```
