// Vulnerable: VUL-CVE-2023-36327
/**
 * Returns a small precomputed prime from a given position in the list of prime
 * numbers.
 *
 * @param[in] pos			- the position in the prime sequence.
 * @return a prime if the position is lower than 512, 0 otherwise.
 */
dig_t bn_get_prime(int pos);

/**
 * Tests if a number is a probable prime.
...
#endif

	util_banner("All tests have passed.\n", 0);
