// Vulnerable: VUL-CVE-2020-24342
/*
** Similar to 'luaD_call', but does not allow yields during the call.
** If there is a stack overflow, freeing all CI structures will
** force the subsequent call to invoke 'luaE_extendCI', which then
** will raise any errors.
*/
void luaD_callnoyield (lua_State *L, StkId func, int nResults) {
...
void luaD_callnoyield (lua_State *L, StkId func, int nResults) {
  incXCcalls(L);
  if (getCcalls(L) <= CSTACKERR)  /* possible stack overflow? */
    luaE_freeCI(L);
  luaD_call(L, func, nResults);
  decXCcalls(L);
