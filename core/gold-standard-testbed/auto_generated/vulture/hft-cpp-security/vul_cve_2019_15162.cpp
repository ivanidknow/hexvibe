// Vulnerable: VUL-CVE-2019-15162
* to another user name.
	 */
	HANDLE Token;
	if (LogonUser(username, ".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &Token) == 0)
...
	 */
	HANDLE Token;
	if (LogonUser(username, ".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &Token) == 0)
	{
...
	if (LogonUser(username, ".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &Token) == 0)
...
		    errno, "setgid");
		return -1;
	}
