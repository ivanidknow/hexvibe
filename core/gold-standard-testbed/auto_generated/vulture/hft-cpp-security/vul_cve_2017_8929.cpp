// Vulnerable: VUL-CVE-2017-8929
//
// Returns:
//    A pointer to the arena's data. NULL if the no data has been written to
//    the arena yet.
//
// --- exec.c ---
#include <math.h>

#include <yara/endian.h>
#include <yara/exec.h>
...
...
// --- object.h ---
void yr_object_destroy(
    YR_OBJECT* object);
