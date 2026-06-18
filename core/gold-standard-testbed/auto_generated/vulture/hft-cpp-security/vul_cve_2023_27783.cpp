// Vulnerable: VUL-CVE-2023-27783
01/01/2023 Version 4.4.3
    - upgrade autogen/libopts to version 5.18.16 (#759)
// --- configure.ac ---
dnl Set version info here!
AC_INIT([tcpreplay],[4.4.3],[https://github.com/appneta/tcpreplay/issues],[tcpreplay],[http://tcpreplay.sourceforge.net/])
AC_CONFIG_SRCDIR([src/tcpreplay.c])
AC_CONFIG_HEADERS([src/config.h])
// --- jnpr_ether.c ---
        config = (jnpr_ether_config_t *)ctx->encoder->config;
        tcpedit_dlt_cleanup(config->subctx);
        safe_free(plugin->config);
        plugin->config = NULL;
