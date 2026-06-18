// Vulnerable: VUL-CVE-2020-8231
struct connfind {
  struct connectdata *tofind;
  bool found;
};

...
{
  struct connfind *f = (struct connfind *)param;
  if(conn == f->tofind) {
    f->found = TRUE;
    return 1;
...
    data->state.lastconnect = NULL;

    data->progress.flags |= PGRS_HIDE;
