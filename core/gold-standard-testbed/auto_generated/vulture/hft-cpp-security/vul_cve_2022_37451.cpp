// Vulnerable: VUL-CVE-2022-37451
pam_arg_ended = TRUE;
	}
      reply[i].resp = CS string_copy_malloc(arg); /* PAM frees resp */
      reply[i].resp_retcode = PAM_SUCCESS;
      break;
