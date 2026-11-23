#!/usr/bin/env python3
"""Lift the AES-GCM-SIV test vectors of RFC 8452 Appendix C into Rust tables.

usage: python3 -I lift_gcm_siv_vectors.py <rfc8452.txt> unit|public

Extended from lift_polyval_vectors.py (phase 1), whose Appendix C parser this keeps. Every value
is located by the RFC's own field labels; nothing is typed in here.

  unit    the table for the unit tests in crypto/symmetric/src/modes/gcm_siv.rs, intermediates included
  public  the table for crypto/symmetric/tests/aes_gcm_siv_rfc8452_tests.rs, inputs and result only
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


def records_of(rfc):
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
            assert label not in cur, (label, cur)
            cur[label] = m.group(2)
            continue
        m = re.match(r"^\s{20,}([0-9a-f]+)$", line)
        if m and cur is not None and label is not None:
            cur[label] += m.group(1)
            continue
        if line.strip() == "":
            continue
        label = None
    return records


def sized(r, prefix):
    """The one field whose label is `prefix (N bytes)`, checked against N."""
    labels = [k for k in r if k.startswith(prefix + " (")]
    assert len(labels) == 1, (prefix, r)
    value = r[labels[0]]
    assert int(re.search(r"\((\d+) bytes\)", labels[0]).group(1)) * 2 == len(value), (prefix, r)
    return value


def main():
    rfc = clean(open(sys.argv[1], encoding="ascii").read())
    mode = sys.argv[2]
    assert mode in ("unit", "public")
    ind = "    " if mode == "unit" else ""
    out = []
    if mode == "unit":
        out.append(ind + "/// RFC 8452 Appendix C: (section, key, nonce, plaintext, AAD, record authentication key,")
        out.append(ind + "/// record encryption key, result) of every vector, in the RFC's order.")
        out.append(ind + "#[rustfmt::skip]")
        out.append(ind + "#[allow(clippy::type_complexity)]")
        out.append(ind + "const APPENDIX_C: &[(&str, &str, &str, &str, &str, &str, &str, &str)] = &[")
    else:
        out.append("/// RFC 8452 Appendix C: (section, key, nonce, plaintext, AAD, result) of every vector, in")
        out.append("/// the RFC's order.")
        out.append("#[rustfmt::skip]")
        out.append("const APPENDIX_C: &[(&str, &str, &str, &str, &str, &str)] = &[")
    counts = {}
    for r in records_of(rfc):
        pt = sized(r, "Plaintext")
        aad = sized(r, "AAD")
        res = sized(r, "Result")
        key, nonce = r["Key"], r["Nonce"]
        ak, ek = r["Record authentication key"], r["Record encryption key"]
        tag, ctr = r["Tag"], r["Initial counter"]
        assert len(key) in (32, 64) and len(ek) == len(key) and len(nonce) == 24, r
        assert len(ak) == 32 and len(tag) == 32 and len(ctr) == 32, r
        assert len(res) == len(pt) + 32 and res.endswith(tag), r
        for v in (pt, aad, res, key, nonce, ak, ek, tag, ctr):
            assert re.fullmatch(r"[0-9a-f]*", v), r
        # "Initial counter" is the tag with the top bit of the last byte set (Section 4).
        assert ctr == tag[:30] + "%02x" % (int(tag[30:], 16) | 0x80), r
        # The section says which AEAD, and so the key length.
        assert len(key) == {"C.1": 32, "C.2": 64, "C.3": 64}[r["section"]], r
        counts[r["section"]] = counts.get(r["section"], 0) + 1
        out.append(f"{ind}    (\"{r['section']}\", \"{key}\", \"{nonce}\",")
        out.append(f"{ind}     \"{pt}\",")
        out.append(f"{ind}     \"{aad}\",")
        if mode == "unit":
            out.append(f"{ind}     \"{ak}\", \"{ek}\",")
        out.append(f"{ind}     \"{res}\"),")
    out.append(ind + "];")
    print("\n".join(out))
    print("counts:", counts, "total", sum(counts.values()), file=sys.stderr)


main()
