// Vulnerable: VUL-CVE-2019-6454
}

static void vtable_member_hash_func(const void *a, struct siphash *state) {
        const struct vtable_member *m = a;

        assert(m);

...
}

static int vtable_member_compare_func(const void *a, const void *b) {
...

void client_id_hash_func(const void *p, struct siphash *state);
int client_id_compare_func(const void *_a, const void *_b);
