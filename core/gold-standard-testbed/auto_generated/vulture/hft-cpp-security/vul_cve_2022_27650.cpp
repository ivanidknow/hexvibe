// Vulnerable: VUL-CVE-2022-27650
capabilities->effective_len = exec_options.cap_size;

capabilities->inheritable = dup_array (exec_options.cap, exec_options.cap_size);
capabilities->inheritable_len = exec_options.cap_size;

capabilities->bounding = dup_array (exec_options.cap, exec_options.cap_size);
