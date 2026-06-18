// Vulnerable: VUL-CVE-2021-29513
#include <cstring>

#include "tensorflow/c/eager/tfe_context_internal.h"
...
  PyObject* value;
  Py_ssize_t pos = 0;
  if (PyDict_Next(descr->fields, &pos, &key, &value)) {
    // In Python 3, the keys of numpy custom struct types are unicode, unlike
