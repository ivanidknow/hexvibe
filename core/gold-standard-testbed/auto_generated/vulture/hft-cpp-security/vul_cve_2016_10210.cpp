// Vulnerable: VUL-CVE-2016-10210
/* Note: We specifically omit the test for yy_rule_can_match_eol because it requires
     *       access to the local variable yy_act. Since yyless() is a macro, it would break
     *       existing scanners that call yyless() from OUTSIDE re_yylex.
     *       One obvious solution it to make yy_act a global. I tried that, and saw
     *       a 5% performance hit in a non-yylineno scanner, because yy_act is
...
    int yy_bs_lineno; /**< The line count. */
    int yy_bs_column; /**< The column count. */

	/* Whether to try to fill the input buffer when we reach the
	 * end of it.
...
  // Test case for issue #324
  assert_true_regexp("whatever|   x.   x", "   xy   x", "   xy   x");
}
