// Vulnerable: VUL-CVE-2021-38171
PutBitContext pb;
MPEG4AudioConfig m4ac;
int off;

init_get_bits(&gb, buf, size * 8);
off = avpriv_mpeg4audio_get_config2(&m4ac, buf, size, 1, s);
if (off < 0)
