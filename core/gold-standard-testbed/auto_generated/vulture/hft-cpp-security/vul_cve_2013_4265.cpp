// Vulnerable: VUL-CVE-2013-4265
void **ptrptr = ptr;
*ptrptr = av_realloc_f(*ptrptr, nmemb, size);
if (!*ptrptr && !(nmemb && size))
    return AVERROR(ENOMEM);
return 0;
