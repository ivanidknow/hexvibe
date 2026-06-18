// Vulnerable: VUL-CVE-2018-20145
1.5.5 - 201812xx
================

Broker:
// --- conf.c ---
		config->listeners[config->listener_count-1].use_subject_as_username = config->default_listener.use_subject_as_username;
#endif
		config->listeners[config->listener_count-1].security_options.password_file = config->default_listener.security_options.password_file;
		config->listeners[config->listener_count-1].security_options.psk_file = config->default_listener.security_options.psk_file;
