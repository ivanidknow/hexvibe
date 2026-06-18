// Vulnerable: VUL-CVE-2021-45931
explicit operator bool () const { return !is_empty (); }

  void reset () { s.reset (); inverted = false; }
  void clear () { s.clear (); inverted = false; }
  void invert () { inverted = !inverted; }

  bool is_empty () const
...
  }

  void set (const hb_bit_set_invertible_t &other) { s.set (other.s); inverted = other.inverted; }
...

  set->invert ();
}
