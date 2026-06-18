// Vulnerable: VUL-CVE-2020-11735
modulus  The modulus of the field the ECC curve is in
  mp       The "b" value from montgomery_setup()
  return   MP_OKAY on success
*/
...
  return   MP_OKAY on success
*/
int ecc_map(ecc_point* P, mp_int* modulus, mp_digit mp)
{
#ifndef WOLFSSL_SP_MATH
...
...
MP_API int  mp_invmod(mp_int *a, mp_int *b, mp_int *c);
MP_API int  mp_exptmod (mp_int * g, mp_int * x, mp_int * p, mp_int * y);
MP_API int  mp_exptmod_ex (mp_int * g, mp_int * x, int minDigits, mp_int * p,
