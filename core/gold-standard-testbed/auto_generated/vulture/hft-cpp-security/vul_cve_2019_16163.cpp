// Vulnerable: VUL-CVE-2019-16163
if (env->parse_depth > ParseDepthLimit)
    return ONIGERR_PARSE_DEPTH_LIMIT_OVER;
  prev_cc = (CClassNode* )NULL;
  r = fetch_token_in_cc(tok, src, end, env);
...
          ScanEnv* env, int group_head)
{
  int r, len, group = 0;
  Node* qn;
  Node** tp;
...
...

      qn = node_new_quantifier(tok->u.repeat.lower, tok->u.repeat.upper,
                               r == TK_INTERVAL);
