// Vulnerable: VUL-CVE-2020-14405
#include "tls.h"


/*
...
          break;
      default:
          buffer=malloc(msg.tc.length+1);
          if (!ReadFromRFBServer(client, buffer, msg.tc.length))
