// Vulnerable: VUL-CVE-2015-1342
TEST_READ: tests/test-read.c
	$(CC) -o tests/test-read tests/test-read.c

TEST_CPUSET: tests/cpusetrange.c cpuset.c
	$(CC) -o tests/cpusetrange tests/cpusetrange.c cpuset.c
...
TEST_CPUSET: tests/cpusetrange.c cpuset.c
	$(CC) -o tests/cpusetrange tests/cpusetrange.c cpuset.c

tests: TEST_READ TEST_CPUSET
...
...
	free(cgdir);
	return ret;
}
