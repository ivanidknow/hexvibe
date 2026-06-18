// Vulnerable: VUL-CVE-2018-19044
file_name = make_file_name(name, prog, namespace, instance);

	log_file = fopen(file_name, "a");
	if (log_file) {
		int n = fileno(log_file);
// --- main.c ---
			__set_bit(NO_SYSLOG_BIT, &debug);
			if (optarg && optarg[0]) {
				int fd = open(optarg, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				if (fd == -1) {
					fprintf(stderr, "Unable to open config-test log file %s\n", optarg);
...
			if ((fifo->fd = open(fifo->name, O_RDWR | O_CLOEXEC | O_NONBLOCK)) == -1) {
				log_message(LOG_INFO, "Unable to open %snotify fifo %s - errno %d", type, fifo->name, errno);
				if (fifo->created_fifo) {
