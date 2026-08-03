"""Unit tests for the vendored normalization/detection logic.

Runs on the standard library alone — no Gradio needed.
    python -m unittest discover -s tests -v
"""

import unittest

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unicode_reveal as ur  # noqa: E402


class TestScan(unittest.TestCase):
    def test_clean_text_has_no_findings(self):
        r = ur.reveal("Please summarize this document.")
        self.assertFalse(r.is_suspicious)
        self.assertEqual(r.findings, [])
        self.assertEqual(r.cleaned, "Please summarize this document.")

    def test_zero_width_detected_and_stripped(self):
        text = "hel​lo"  # zero width space
        r = ur.reveal(text)
        cats = [f.category for f in r.findings]
        self.assertIn("zero-width", cats)
        self.assertEqual(r.cleaned, "hello")

    def test_hidden_instruction_zero_width_joined(self):
        # "ignore all previous instructions" hidden with ZWSP between letters.
        hidden = "​".join("ignore previous")
        text = f"cute cat pic {hidden}"
        r = ur.reveal(text)
        self.assertTrue(r.is_suspicious)
        self.assertIn("ignore previous", r.cleaned)

    def test_bidi_override_detected(self):
        text = "safe‮elifreganam"  # RIGHT-TO-LEFT OVERRIDE
        r = ur.reveal(text)
        cats = [f.category for f in r.findings]
        self.assertIn("bidi", cats)
        self.assertNotIn("‮", r.cleaned)

    def test_tag_block_mirrors_ascii(self):
        # Encode "hi" invisibly in the Unicode tag block.
        tagged = "".join(chr(0xE0000 + ord(c)) for c in "hi")
        text = f"emoji{tagged}"
        r = ur.reveal(text)
        tag_findings = [f for f in r.findings if f.category == "tag-block"]
        self.assertEqual(len(tag_findings), 2)
        self.assertIn("mirrors ASCII", tag_findings[0].note)
        self.assertEqual(r.cleaned, "emoji")

    def test_homoglyph_cyrillic_ignore(self):
        # "іgnоrе" using Cyrillic i (U+0456), o (U+043E), e (U+0435).
        text = "іgnоrе"
        r = ur.reveal(text)
        homo = [f for f in r.findings if f.category == "homoglyph"]
        self.assertGreaterEqual(len(homo), 3)
        self.assertEqual(r.cleaned, "ignore")

    def test_fullwidth_latin_homoglyph(self):
        text = "Ｉｇｎｏｒｅ"  # Ｉｇｎｏｒｅ
        r = ur.reveal(text)
        self.assertEqual(r.cleaned, "Ignore")
        self.assertTrue(all(f.category == "homoglyph" for f in r.findings))

    def test_turkish_casefold_trap(self):
        # dotless i and dotted capital I
        text = "gızlİ"  # gızlİ
        r = ur.reveal(text)
        traps = [f for f in r.findings if f.category == "casefold-trap"]
        self.assertGreaterEqual(len(traps), 2)

    def test_byte_offset_accuracy(self):
        text = "a​b"  # 'a', ZWSP (3 UTF-8 bytes), 'b'
        r = ur.reveal(text)
        f = r.findings[0]
        self.assertEqual(f.offset, 1)
        self.assertEqual(f.byte_offset, 1)  # 'a' is 1 byte

    def test_byte_offset_after_multibyte_prefix(self):
        # 'ç' (U+00E7) is 2 UTF-8 bytes, 'ö' (U+00F6) is 2 bytes, then ZWSP.
        # Char index 2 must map to byte offset 4, proving byte_offset tracks
        # true UTF-8 width and is not merely the character index.
        text = "çö​x"
        r = ur.reveal(text)
        zw = [f for f in r.findings if f.category == "zero-width"][0]
        self.assertEqual(zw.offset, 2)
        self.assertEqual(zw.byte_offset, 4)

    def test_variation_selector_detected(self):
        # VARIATION SELECTOR-16 (U+FE0F) is an invisible payload channel.
        text = "a️b"
        r = ur.reveal(text)
        cats = [f.category for f in r.findings]
        self.assertIn("variation-selector", cats)
        self.assertEqual(r.cleaned, "ab")

    def test_astral_tag_block_char_index_is_codepoint_based(self):
        # A tag-block char (U+E0041) is astral (>U+FFFF). The finding index must
        # be a code-point index (1), not a UTF-16 surrogate-pair index (would
        # be 2 if the scanner iterated code units).
        text = "x" + chr(0xE0041)  # tag 'A'
        f = ur.scan(text)[0]
        self.assertEqual(f.offset, 1)
        self.assertEqual(f.category, "tag-block")
        self.assertIn("mirrors ASCII 'A'", f.note)

    def test_plain_ascii_and_latin_i_not_over_flagged(self):
        # Regular ASCII 'i'/'I' and normal accented Latin must NOT be flagged;
        # only the Turkish dotless-i family is a casefold trap. Guards against
        # a scanner that flags every non-ASCII or every 'i'.
        r = ur.reveal("I insist: naïve café")
        self.assertFalse(r.is_suspicious)
        self.assertEqual(r.findings, [])

    def test_u_property_format(self):
        text = "​"
        f = ur.scan(text)[0]
        self.assertEqual(f.u, "U+200B")

    def test_counts(self):
        text = "​‌‮"
        r = ur.reveal(text)
        c = r.counts()
        self.assertEqual(c.get("zero-width"), 2)
        self.assertEqual(c.get("bidi"), 1)

    def test_neutralize_is_idempotent_on_clean(self):
        clean = ur.neutralize("normal ASCII text 123")
        self.assertEqual(clean, "normal ASCII text 123")
        self.assertEqual(ur.neutralize(clean), clean)

    def test_nfkc_collapses_compatibility(self):
        # Circled/ligature compatibility form should fold under NFKC.
        text = "ﬁle"  # ﬁ ligature + "le"
        self.assertEqual(ur.neutralize(text), "file")

    def test_soft_hyphen_stripped(self):
        text = "pass­word"
        r = ur.reveal(text)
        self.assertEqual(r.cleaned, "password")
        self.assertIn("zero-width", [f.category for f in r.findings])


if __name__ == "__main__":
    unittest.main()
