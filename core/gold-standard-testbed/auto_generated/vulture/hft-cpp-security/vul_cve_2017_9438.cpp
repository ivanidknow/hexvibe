// Vulnerable: VUL-CVE-2017-9438
((RE_AST*) yyget_extra(yyscanner))->flags &= ~RE_FLAGS_FAST_REGEXP

#define ERROR_IF(x, error) \
    if (x) \
...


#line 111 "hex_grammar.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
...
...
        mark_as_not_fast_regexp();

        $$ = yr_re_node_create(RE_NODE_ALT, $1, $3);
