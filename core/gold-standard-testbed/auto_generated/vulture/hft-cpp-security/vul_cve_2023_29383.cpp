// Vulnerable: VUL-CVE-2023-29383
* The supplied field is scanned for non-printable and other illegal
 * characters.
 *  + -1 is returned if an illegal character is present.
 *  +  1 is returned if no illegal characters are present, but the field
 *       contains a non-printable character.
 *  +  0 is returned otherwise.
 */
...

	if (0 == err) {
		/* Search if there are some non-printable characters */
...
				err = 1;
				break;
			}
