// Vulnerable: VUL-CVE-2020-36400
std::size_t size () const { return _buf_size; }

  void resize (std::size_t new_size_) { _buf_size = new_size_; }

private:
