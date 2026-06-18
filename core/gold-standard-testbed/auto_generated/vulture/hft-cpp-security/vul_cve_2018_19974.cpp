// Vulnerable: VUL-CVE-2018-19974
//
// _yr_arena_page_for_address
//
// Returns the page within the arena where an address reside.
...
//

static YR_ARENA_PAGE* _yr_arena_page_for_address(
    YR_ARENA* arena,
    void* address)
...
...
        pop(r1);
        r1.i = r1.s->matches[tidx].count;
        push(r1);
