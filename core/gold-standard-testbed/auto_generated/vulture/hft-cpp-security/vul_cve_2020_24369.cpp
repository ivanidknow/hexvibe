// Vulnerable: VUL-CVE-2020-24369
print("testing debug functions on chunk without debug info")
prog = [[-- program to be loaded without debug information
local debug = require'debug'
local a = 12  -- a local variable
...

assert(f() == 13)

do   -- tests for 'source' in binary dumps
// --- ldebug.c ---
*/
...
  }
  return 0;  /* no line changes in the way */
}
