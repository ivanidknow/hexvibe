// Vulnerable: VUL-CVE-2023-32067
struct server_state *server;
  int i;
  ares_ssize_t count;
  unsigned char buf[MAXENDSSZ + 1];
#ifdef HAVE_RECVFROM
...
       * packets as we can. */
      do {
        if (server->udp_socket == ARES_SOCKET_BAD)
          count = 0;

...
       } while (count > 0);
    }
}
