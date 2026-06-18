# Vulnerable: VUL-CVE-2017-5924
| _FOR_ for_expression error
  {
    compiler->loop_depth--;
    compiler->loop_identifier[compiler->loop_depth] = NULL;
  }
| _FOR_ for_expression _IDENTIFIER_ _IN_
