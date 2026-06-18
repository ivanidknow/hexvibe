// Vulnerable: VUL-CVE-2019-13045
g_free_not_null(ircconn->usermode);
	g_free_not_null(ircconn->alternate_nick);
}
// --- irc-servers-reconnect.c ---
	rec->alternate_nick = g_strdup(src->alternate_nick);
	rec->sasl_mechanism = src->sasl_mechanism;
	rec->sasl_username = src->sasl_username;
	rec->sasl_password = src->sasl_password;
	*dest = (SERVER_CONNECT_REC *) rec;
}
// --- irc-servers-setup.c ---
...
				conn->sasl_password = ircnet->sasl_password;
			} else
				g_warning("The fields sasl_username and sasl_password are either missing or empty");
