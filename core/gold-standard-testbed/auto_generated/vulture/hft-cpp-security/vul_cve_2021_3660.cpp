// Vulnerable: VUL-CVE-2021-3660
"default-src 'self' https://127.0.0.1:9090; connect-src 'self' https://127.0.0.1:9090 wss://127.0.0.1:9090", headers)
        self.assertIn("Access-Control-Allow-Origin: https://127.0.0.1:9090", headers)
        # CORP is also set for dynamic paths
        self.assertIn("Cross-Origin-Resource-Policy: same-origin", headers)

...
        # CORP is also set for dynamic paths
        self.assertIn("Cross-Origin-Resource-Policy: same-origin", headers)

        self.allow_journal_messages(
...
...
    Cockpit components can be integrated.</para>

  <section id="embedding-full">
