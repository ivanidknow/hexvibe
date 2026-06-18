// Vulnerable: VUL-CVE-2021-24036
#include <cstdint>
#include <cstdlib>
#include <stdexcept>

...
#include <folly/io/Cursor.h>
#include <folly/lang/Align.h>
#include <folly/lang/Exception.h>
#include <folly/memory/Malloc.h>
...
  // difference.  Callers that know their exact use case can also explicitly
...
size_t IOBuf::goodExtBufferSize(std::size_t minCapacity) {
  // Determine how much space we should allocate.  We'll store the SharedInfo
  // for the external buffer just after the buffer itself.  (We store it just
