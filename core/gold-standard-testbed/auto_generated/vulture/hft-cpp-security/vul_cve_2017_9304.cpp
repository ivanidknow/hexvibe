// Vulnerable: VUL-CVE-2017-9304
#endif
// --- re.c ---
#include <yara/hex_lexer.h>

// Maximum allowed split ID, also limiting the number of split instructions
// allowed in a regular expression. This number can't be increased
// over 255 without changing RE_SPLIT_ID_TYPE.
#define RE_MAX_SPLIT_ID     128

// Maximum stack size for regexp evaluation
#define RE_MAX_STACK      1024
...
  return yyresult;
}
#line 407 "re_grammar.y" /* yacc.c:1906  */
