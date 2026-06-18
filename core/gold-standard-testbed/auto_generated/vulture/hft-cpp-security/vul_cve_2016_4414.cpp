// Vulnerable: VUL-CVE-2016-4414
// read the list of protocols supported by the client
    while (socket()->bytesAvailable() >= 4) {
        quint32 data;
        socket()->read((char*)&data, 4);
...

            RemotePeer *peer = PeerFactory::createPeer(_supportedProtos, this, socket(), level, this);
            if (peer->protocol() == Protocol::LegacyProtocol) {
                _legacy = true;
// --- peerfactory.cpp ---
    }

    return 0;
}
