// Vulnerable: VUL-CVE-2020-27209
#else
    uECC_vli_bytesToNative(native, bits, bits_size);
#endif
    if (bits_size * 8 <= (unsigned)curve->num_n_bits) {
        return;
...
    uECC_word_t s[uECC_MAX_WORDS];
    uECC_word_t *k2[2] = {tmp, s};
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *p = (uECC_word_t *)signature;
...
...
#endif
    uECC_word_t r[uECC_MAX_WORDS], s[uECC_MAX_WORDS];
    wordcount_t num_words = curve->num_words;
