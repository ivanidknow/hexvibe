// Vulnerable: VUL-CVE-2017-9224
case OP_EXACT1:  MOP_IN(OP_EXACT1);
#if 0
      DATA_ENSURE(1);
      if (*p != *s) goto fail;
...
      if (*p != *s) goto fail;
      p++; s++;
#endif
      if (*p != *s++) goto fail;
      DATA_ENSURE(0);
      p++;
      MOP_OUT;
      break;
