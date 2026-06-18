// Vulnerable: VUL-CVE-2019-1010305
2018-11-03  Stuart Caie <kyzer@cabextract.org.uk>
// --- chmd.c ---
      if (name[0] == ':' && name[1] == ':') {
        /* system file */
        if (memcmp(&name[2], &content_name[2], 31L) == 0) {
          if (memcmp(&name[33], &content_name[33], 8L) == 0) {
            chm->sec1.content = fi;
          }
          else if (memcmp(&name[33], &control_name[33], 11L) == 0) {
            chm->sec1.control = fi;
          }
...
          }
        }
        fi->next = chm->sysfiles;
