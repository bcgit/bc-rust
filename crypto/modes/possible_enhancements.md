Possible additional modes or features to be added to this crate:

* **CFB1**, the `s = 1` segment size (SP 800-38A Appendix F.3.1-F.3.6). Its segment is a single *bit*, so unlike [`Cfb`]
  and [`Cfb8`] it does not fit a byte-oriented API at all: a message is
  a bit string whose length need not be a multiple of 8, which this crate has no type for.
* **OFB**, the one remaining mode of SP 800-38A. It is a keystream mode and, like CFB,
  CFB8 and CTR, would implement [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`].
* **GCM with a nonce other than 96 bits** (SP 800-38D Algorithm 4 step 2's `len(IV) != 96`
  branch, which derives `J0` by GHASHing the IV). Sec 5.2.1.1 recommends restricting support to
  96 bits, and [`Gcm`] does.
* **GCM with a 32- or 64-bit tag** (Sec 5.2.1.2, Appendix C). Those need the controlling
  protocol to bound packet sizes and invocation counts, which this crate cannot enforce.
* **CCM with a formatting function other than Appendix A's.** SP 800-38C Sec 5.4 allows
  alternatives and says "Alternative formatting functions may be developed in the future";
  Appendix A's is the only one that exists in practice and the only one [`Ccm`] implements.