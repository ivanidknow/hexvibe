// Vulnerable: VUL-CVE-2022-35252
}
  return TRUE;
}

...
          done = TRUE;
          if(!co->name || !co->value) {
            badcookie = TRUE;
            break;
