// Vulnerable: JAVA-220
SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1", "TLSv1.1", "SSLv3"},
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }
}
class Ok {
    public void ok_disable_old_tls1() {
