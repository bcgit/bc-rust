#!/usr/bin/env python3
"""Lift the POLYVAL test values from RFC 8452 and its errata page into Rust consts.

usage: python3 -I lift_polyval_vectors.py <rfc8452.txt> <errata-rfc8452.html>

Every value is located by the RFC's own wording; nothing is typed in here. The output is the
block between the BEGIN/END markers in crypto/symmetric/src/modes/polyval.rs.
"""
import re
import sys


def clean(text):
    """Drop the page footers, form feeds and page headers, keeping line structure."""
    out = []
    for line in text.replace("\f", "\n").split("\n"):
        if re.match(r"^Gueron, et al\.\s+Informational\s+\[Page \d+\]$", line):
            continue
        if re.match(r"^RFC 8452\s+AES-GCM-SIV\s+April 2019$", line):
            continue
        out.append(line)
    return "\n".join(out)


def section(text, start, end):
    i = text.index("\n" + start)
    j = text.index("\n" + end, i + 1)
    return text[i:j]


def one(pattern, text, what):
    flat = re.sub(r"\s+", " ", text)
    m = re.findall(pattern, flat)
    if len(m) != 1:
        sys.exit(f"{what}: expected one match, found {len(m)}")
    return m[0]


H32 = r"([0-9a-f]{32})"


def const(name, value, doc):
    assert re.fullmatch(r"[0-9a-f]*", value), (name, value)
    return f"    /// {doc}\n    const {name}: &str = \"{value}\";"


def main():
    rfc = clean(open(sys.argv[1], encoding="ascii").read())
    errata = open(sys.argv[2], encoding="utf-8", errors="replace").read()
    out = []

    # Section 7.
    s7 = section(rfc, "7.  Field Operation Examples", "8.  Worked Example")
    out.append(const("S7_X_INV_128", one(r"the sixteen bytes " + H32 + r" would represent", s7, "x^-128"),
                     "Section 7: the value of `x^-128`."))
    out.append(const("S7_A", one(r"If a = " + H32, s7, "a"), "Section 7: `a`."))
    out.append(const("S7_B", one(r"If a = [0-9a-f]{32} and b = " + H32, s7, "b"), "Section 7: `b`."))
    out.append(const("S7_A_PLUS_B", one(r"a \+ b = " + H32, s7, "a+b"), "Section 7: `a + b`."))
    out.append(const("S7_A_TIMES_B", one(r"a \* b = " + H32, s7, "a*b"), "Section 7: `a * b`."))
    out.append(const("S7_DOT_A_B", one(r"dot\(a, b\) = " + H32, s7, "dot"), "Section 7: `dot(a, b)`."))

    # Section 8.
    s8 = section(rfc, "8.  Worked Example", "9.  Security Considerations")
    out.append(const("S8_AUTH_KEY", one(r"message-authentication key is " + H32, s8, "s8 key"),
                     "Section 8: the message-authentication key."))
    flat8 = re.sub(r"\s+", " ", s8)
    m = re.search(r"padded plaintext, and then the length block\. This is ([0-9a-f ]+), based on", flat8)
    if not m:
        sys.exit("s8 input not found")
    s8_input = m.group(1).replace(" ", "")
    assert len(s8_input) == 96, len(s8_input)
    out.append(const("S8_INPUT", s8_input, "Section 8: the input to POLYVAL."))
    out.append(const("S8_RESULT", one(r"results in S_s = " + H32, s8, "s8 result"),
                     "Section 8: `S_s`."))

    # Appendix A.
    a = section(rfc, "Appendix A.  The Relationship between POLYVAL and GHASH",
                "Appendix B.  Additional Comparisons with AES-GCM")
    g = one(r"Given the 16-byte string " + H32 + r", mulX_GHASH of that string is " + H32
            + r" and mulX_POLYVAL of that string is " + H32, a, "mulX first")
    out.append(const("A_MULX_IN_1", g[0], "Appendix A: the first `mulX` example's input."))
    out.append(const("A_MULX_GHASH_1", g[1], "Appendix A: its `mulX_GHASH`."))
    out.append(const("A_MULX_POLYVAL_1", g[2], "Appendix A: its `mulX_POLYVAL`."))
    g = one(r"given " + H32 + r", mulX_GHASH of that string is " + H32
            + r" and mulX_POLYVAL of it is " + H32, a, "mulX second")
    out.append(const("A_MULX_IN_2", g[0], "Appendix A: the second `mulX` example's input."))
    out.append(const("A_MULX_GHASH_2", g[1], "Appendix A: its `mulX_GHASH`."))
    rfc_typo = g[2]
    # Erratum 5854 (Verified) replaces the RFC's mulX_POLYVAL value for the second example.
    eflat = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", errata))
    if not re.search(r"Errata-ID: 5854 Status: Verified", eflat):
        sys.exit("erratum 5854 not found as Verified")
    says = one(r"says: \.\.\.mulX_POLYVAL of it is " + H32, eflat, "erratum says")
    should = one(r"should say: \.\.\.mulX_POLYVAL of it is " + H32, eflat, "erratum should say")
    assert says == rfc_typo, "the erratum does not quote the RFC text"
    out.append(const("A_MULX_POLYVAL_2_AS_PRINTED", rfc_typo,
                     "Appendix A as printed: its `mulX_POLYVAL`, which erratum 5854 corrects."))
    out.append(const("A_MULX_POLYVAL_2", should,
                     "RFC Editor erratum 5854 (Verified): the corrected `mulX_POLYVAL`."))
    g = one(r"let H = " + H32 + r", X_1 = " + H32 + r", and X_2 = " + H32
            + r"\. POLYVAL\(H, X_1, X_2\) = " + H32, a, "A worked")
    out.append(const("A_H", g[0], "Appendix A worked example: `H`."))
    out.append(const("A_X1", g[1], "Appendix A worked example: `X_1`."))
    out.append(const("A_X2", g[2], "Appendix A worked example: `X_2`."))
    out.append(const("A_POLYVAL", g[3], "Appendix A worked example: `POLYVAL(H, X_1, X_2)`."))
    out.append(const("A_GHASH_KEY", one(r"mulX_GHASH\(ByteReverse\(H\)\) = " + H32, a, "ghash key"),
                     "Appendix A worked example: `mulX_GHASH(ByteReverse(H))`."))
    again = one(r"Then ByteReverse\(GHASH\(dcba\.\.\., ByteReverse\(X_1\), ByteReverse\(X_2\)\)\) = " + H32,
                a, "A polyval again")
    assert again == g[3]
    gh = one(r"GHASH\(H, X_1, X_2\) = " + H32, a, "A ghash")
    out.append(const("A_GHASH", gh, "Appendix A worked example: `GHASH(H, X_1, X_2)`."))
    out.append(const("A_POLYVAL_KEY", one(r"mulX_POLYVAL\(ByteReverse\(H\)\) = " + H32, a, "polyval key"),
                     "Appendix A worked example: `mulX_POLYVAL(ByteReverse(H))`."))
    again = one(r"Then ByteReverse\(POLYVAL\(f6ea\.\.\., ByteReverse\(X_1\), ByteReverse\(X_2\)\)\) = " + H32,
                a, "A ghash again")
    assert again == gh

    # Appendix C: one record per blank-line-separated group of "Label = hex" fields.
    c = rfc[rfc.index("\nAppendix C.  Test Vectors"):rfc.index("\nAcknowledgements")]
    records = []
    sec = None
    cur = None
    label = None
    for line in c.split("\n"):
        m = re.match(r"^(C\.\d)\.  ", line)
        if m:
            sec = m.group(1)
            continue
        m = re.match(r"^   (\S[^=]*?) =\s*([0-9a-f]*)$", line)
        if m:
            label = m.group(1)
            if label.startswith("Plaintext ("):
                cur = {"section": sec}
                records.append(cur)
            cur[label] = m.group(2)
            continue
        m = re.match(r"^\s{20,}([0-9a-f]+)$", line)
        if m and cur is not None and label is not None:
            cur[label] += m.group(1)
            continue
        if line.strip() == "":
            continue
        label = None

    out.append("")
    out.append("    /// Appendix C: (section, plaintext, AAD, record authentication key, POLYVAL input,")
    out.append("    /// POLYVAL result) of every vector, in the RFC's order.")
    out.append("    #[rustfmt::skip]")
    out.append("    const APPENDIX_C: &[(&str, &str, &str, &str, &str, &str)] = &[")
    counts = {}
    for r in records:
        pt = [v for k, v in r.items() if k.startswith("Plaintext (")]
        aad = [v for k, v in r.items() if k.startswith("AAD (")]
        ptl = [k for k in r if k.startswith("Plaintext (")][0]
        aadl = [k for k in r if k.startswith("AAD (")][0]
        assert len(pt) == 1 and len(aad) == 1, r
        assert int(re.search(r"\((\d+) bytes\)", ptl).group(1)) * 2 == len(pt[0]), r
        assert int(re.search(r"\((\d+) bytes\)", aadl).group(1)) * 2 == len(aad[0]), r
        key, inp, res = r["Record authentication key"], r["POLYVAL input"], r["POLYVAL result"]
        assert len(key) == 32 and len(res) == 32 and len(inp) % 32 == 0 and len(inp) >= 32, r
        counts[r["section"]] = counts.get(r["section"], 0) + 1
        out.append(f"        (\"{r['section']}\", \"{pt[0]}\", \"{aad[0]}\",")
        out.append(f"         \"{key}\",")
        out.append(f"         \"{inp}\",")
        out.append(f"         \"{res}\"),")
    out.append("    ];")
    print("\n".join(out))
    print("counts:", counts, "total", len(records), file=sys.stderr)


main()
