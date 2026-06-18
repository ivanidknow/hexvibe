// Vulnerable: VUL-CVE-2020-15889
/*
** Does a young collection. First, mark 'OLD1' objects.  (Only survival
** and "recent old" lists can contain 'OLD1' objects. New lists cannot
** contain 'OLD1' objects, at most 'OLD0' objects that were already
** visited when marked old.) Then does the atomic step. Then,
** sweep all lists and advance pointers. Finally, finish the collection.
*/
static void youngcollection (lua_State *L, global_State *g) {
...
  GCObject **psurvival;  /* to point to first non-dead survival object */
  lua_assert(g->gcstate == GCSpropagate);
  markold(g, g->survival, g->reallyold);
  markold(g, g->finobj, g->finobjrold);
  atomic(L);
