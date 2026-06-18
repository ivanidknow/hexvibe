// Vulnerable: VUL-CVE-2018-18585
2018-10-16  Stuart Caie <kyzer@cabextract.org.uk>
// --- chmd.c ---
      READ_ENCINT(name_len);
      if (name_len > (unsigned int) (end - p)) goto chunk_end;
      /* consider blank filenames to be an error */
      if (name_len == 0) goto chunk_end;
      name = p; p += name_len;

...
      if (name_len == 0) goto chunk_end;
      name = p; p += name_len;
...
      READ_ENCINT(length);

      /* empty files and directory names are stored as a file entry at
