// Vulnerable: VUL-CVE-2023-1672
const char* alg[] = {"ES512", "ECMR", NULL};
    char path[PATH_MAX];
    for (int i = 0; alg[i] != NULL; i++) {
        json_auto_t* jwk = jwk_generate(alg[i]);
// --- tangd-keygen.in ---
THP_DEFAULT_HASH=S256     # SHA-256.
jwe=$(jose jwk gen -i '{"alg":"ES512"}')
[ -z "$sig" ] && sig=$(echo "$jwe" | jose jwk thp -i- -a "${THP_DEFAULT_HASH}")
// --- tangd-rotate-keys.in ---
    # Create a new set of keys.
    DEFAULT_THP_HASH="S256"
    for alg in "ES512" "ECMR"; do
        json="$(printf '{"alg": "%s"}' "${alg}")"
