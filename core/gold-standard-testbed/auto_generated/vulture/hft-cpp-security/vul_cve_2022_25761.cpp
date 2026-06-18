// Vulnerable: VUL-CVE-2022-25761
UA_SecureChannel_setSecurityPolicy(&testChannel, &dummyPolicy, &dummyCertificate);

    testingConnection = createDummyConnection(65535, &sentData);
    UA_Connection_attachSecureChannel(&testingConnection, &testChannel);
    testChannel.connection = &testingConnection;
// --- ua_config_default.c ---
const UA_ConnectionConfig UA_ConnectionConfig_default = {
    0,     /* .protocolVersion */
    65535, /* .sendBufferSize, 64k per chunk */
    65535, /* .recvBufferSize, 64k per chunk */
    0,     /* .localMaxMessageSize, 0 -> unlimited */
...
    0,     /* .localMaxChunkCount, 0 -> unlimited */
    0      /* .remoteMaxChunkCount, 0 -> unlimited */
};
