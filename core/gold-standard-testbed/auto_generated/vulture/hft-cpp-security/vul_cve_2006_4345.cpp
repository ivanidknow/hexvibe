// Vulnerable: VUL-CVE-2006-4345
strncasecmp(v, p->sub->next->cxident, len)) {
							/* connection id not found. delete it */
							char cxident[80];
							memcpy(cxident, v, len);
							cxident[len] = '\0';
							if (option_verbose > 2) {
								ast_verbose(VERBOSE_PREFIX_3 "Non existing connection id %s on %s@%s \n",
...
							if (option_verbose > 2) {
								ast_verbose(VERBOSE_PREFIX_3 "Non existing connection id %s on %s@%s \n",
									cxident, p->name, gw->name);
							}
							transmit_connection_del_w_params(p, NULL, cxident);
