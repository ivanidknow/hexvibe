// Vulnerable: VUL-CVE-2017-18212
#include "ecma-builtin-internal-routines-template.inc.h"

/** \addtogroup ecma ECMA
 * @{
...
        case LIT_CHAR_LOWERCASE_U:
        {
          ecma_char_t code_unit;
          if ((end_p - current_p >= 2) && !(lit_read_code_unit_from_hex (current_p + 1, 4, &code_unit)))
          {
            return;
...
          current_p += 5;
          write_p += lit_code_unit_to_utf8 (code_unit, write_p);
          continue;
