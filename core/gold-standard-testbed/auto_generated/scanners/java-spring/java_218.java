// Vulnerable: JAVA-218
DefaultFtpSessionFactory ftpSessionFactory = new DefaultFtpSessionFactory();
        String url = "ftp://example.com";
        ftpSessionFactory.setHost(url);
        ftpSessionFactory.setPort(properties.getPort());
        ftpSessionFactory.setUsername(properties.getUsername());
        ftpSessionFactory.setPassword(properties.getPassword());
        ftpSessionFactory.setClientMode(properties.getClientMode().getMode());
        if (properties.getCacheSessions() != null) {
            CachingSessionFactory<FTPFile> csf = new CachingSessionFactory<>(ftpSessionFactory);
            return csf;
...
    @ConditionalOnMissingBean
    public SessionFactory<FTPFile> ok1(FtpSessionFactoryProperties properties) {
