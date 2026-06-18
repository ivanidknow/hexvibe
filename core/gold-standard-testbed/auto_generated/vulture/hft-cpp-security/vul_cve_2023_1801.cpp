// Vulnerable: VUL-CVE-2023-1801
extern void signed_relts_print(netdissect_options *, int32_t);
extern void unsigned_relts_print(netdissect_options *, uint32_t);

extern void fn_print_char(netdissect_options *, u_char);
// --- ntp.c ---
	    int64_t seconds_64bit = (int64_t)i - JAN_1970;
	    time_t seconds;
	    struct tm *tm;
	    char time_buf[128];

...
...
	else
		ND_PRINT("%s.%09u", buf, nanoseconds);
}
