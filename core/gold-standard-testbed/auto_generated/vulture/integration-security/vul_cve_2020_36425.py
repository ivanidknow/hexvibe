# Vulnerable: VUL-CVE-2020-36425
$(OPENSSL) ca -gencrl -batch -cert $(test_ca_crt) -keyfile $(test_ca_key_file_rsa) -key $(test_ca_pwd_rsa) -config $(test_ca_server1_config_file) -md sha1 -crldays 3653 -out $@

server1_all: crl.pem server1.crt server1.noauthid.crt server1.crt.openssl server1.v1.crt server1.v1.crt.openssl server1.key_usage.crt server1.key_usage_noauthid.crt server1.key_usage.crt.openssl server1.cert_type.crt server1.cert_type_noauthid.crt server1.cert_type.crt.openssl server1.der server1.der.openssl server1.v1.der server1.v1.der.openssl server1.key_usage.der server1.key_usage.der.openssl server1.cert_type.der server1.cert_type.der.openssl

# server2*
// --- Readme-x509.txt ---
- crl-future.pem: (2) server6.crt + unknown
- crl-rsa-pss-*.pem: (1) server9{,badsign,with-ca}.crt + cert_sha384.crt + unknown
- crl.pem, crl_expired.pem: (1) server1{,.cert_type,.key_usage,.v1}.crt + unknown
- crl_md*.pem: crl_sha*.pem: (1) same as crl.pem
- crt_cat_*.pem: (1+2) concatenations in various orders:
...

component_test_platform_calloc_macro () {
    msg "build: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
