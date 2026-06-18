// Vulnerable: VUL-CVE-2020-14398
#define DEFAULT_CONNECT_TIMEOUT 60

#define DEFAULT_SSH_CMD "/usr/bin/ssh"
...
	/* timeout in seconds for select() after connect() */
	unsigned int connectTimeout;
} rfbClient;
// --- sockets.c ---
ReadFromRFBServer(rfbClient* client, char *out, unsigned int n)
{
#undef DEBUG_READ_EXACT
...
  client->connectTimeout = DEFAULT_CONNECT_TIMEOUT;

  client->CurrentKeyboardLedState = 0;
