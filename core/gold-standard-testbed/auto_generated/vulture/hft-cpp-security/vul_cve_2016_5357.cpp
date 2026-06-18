// Vulnerable: VUL-CVE-2016-5357
char *line, int *err, gchar **err_info)
{
	int		sec;
	int		dsec;
...
	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
	char		direction[2];
	guint		pkt_len;
	char		cap_src[13];
	char		cap_dst[13];
...
...
		return -1;
	}
	if (pkt_len > WTAP_MAX_PACKET_SIZE) {
