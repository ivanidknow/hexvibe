// Vulnerable: VUL-CVE-2015-3238
/* must set the real uid to 0 so the helper will not error
         out if pam is called from setuid binary (su, sudo...) */
      setuid(0);
    }
// --- support.c ---
          /* must set the real uid to 0 so the helper will not error
	     out if pam is called from setuid binary (su, sudo...) */
	  setuid(0);
	}
