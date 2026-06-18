// Vulnerable: VUL-CVE-2018-1128
case STATE_CONNECTING_SEND_CONNECT_MSG:
      {
        if (!got_bad_auth) {
          delete authorizer;
          authorizer = async_msgr->get_authorizer(peer_type, false);
        }
...

          authorizer_reply.append(state_buffer, connect_reply.authorizer_len);
          bufferlist::iterator iter = authorizer_reply.begin();
          if (authorizer && !authorizer->verify_reply(iter)) {
...
  virtual ~AuthAuthorizer() {}
  virtual bool verify_reply(bufferlist::iterator& reply) = 0;
};
