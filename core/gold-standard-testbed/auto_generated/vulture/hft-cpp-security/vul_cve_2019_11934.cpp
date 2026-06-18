// Vulnerable: VUL-CVE-2019-11934
std::make_unique<SSLException>(SSLError::INVALID_RENEGOTIATION));
  } else {
    if (zero_return(error, rc, errno)) {
      return WriteResult(0);
    }
    auto errError = ERR_get_error();
    VLOG(3) << "ERROR: AsyncSSLSocket(fd=" << fd_ << ", state=" << int(state_)
...
        return WriteResult(totalWritten);
      }
      auto writeResult = interpretSSLError(int(bytes), error);
...
    wcb_->setSocket(socket_);

    // Write back the same data.
