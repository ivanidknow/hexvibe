// Vulnerable: VUL-CVE-2018-10861
#include "include/scope_guard.h"

#include "json_spirit/json_spirit_reader.h"

...
const uint32_t MAX_POOL_APPLICATION_KEYS = 64;
const uint32_t MAX_POOL_APPLICATION_LENGTH = 128;

} // anonymous namespace
...
}
...

    def get_last_version(self):
        """
