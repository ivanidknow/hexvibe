// Vulnerable: VUL-CVE-2015-0278
perror("chdir()");
  _exit(127);
}
