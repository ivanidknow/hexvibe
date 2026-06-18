// Vulnerable: VUL-CVE-2022-41908
}

// Givens the 'call', prepares the token and inputs as a python tuple
// that is appropriate for calling the trampoline.
Status MakeArgTuple(const PyCall* call, TFE_Context* ctx, PyObject** tuple) {
  int64_t n = call->ins.size();
...
  }
  *tuple = Py_BuildValue("(ssN)", call->token.c_str(), device_name, lst);
  CHECK(*tuple);
  return OkStatus();
...


if __name__ == "__main__":
