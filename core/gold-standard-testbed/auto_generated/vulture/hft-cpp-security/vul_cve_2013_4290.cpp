// Vulnerable: VUL-CVE-2013-4290
int str_length/*, i, j*/; /* UniPG */
		char message[MSG_SIZE];
		memset(message, 0, MSG_SIZE);
		/* initialize the optional parameter list */
		va_start(arg, fmt);
...
		/* initialize the optional parameter list */
		va_start(arg, fmt);
		/* check the length of the format string */
		str_length = (strlen(fmt) > MSG_SIZE) ? MSG_SIZE : strlen(fmt);
		/* parse the format string and put the result in 'message' */
...
		/* output the message to the user program */
		msg_handler(message, cinfo->client_data);
	}
