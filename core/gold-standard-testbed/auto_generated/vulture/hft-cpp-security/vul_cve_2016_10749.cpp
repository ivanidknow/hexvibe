// Vulnerable: VUL-CVE-2016-10749
const char *ptr=str+1,*end_ptr=str+1;char *ptr2;char *out;int len=0;unsigned uc,uc2;
if (*str!='\"') {*ep=str;return 0;}	/* not a string! */

while (*end_ptr!='\"' && *end_ptr && ++len) if (*end_ptr++ == '\\') end_ptr++;	/* Skip escaped quotes. */

out=(char*)cJSON_malloc(len+1);	/* This is how long we need for the string, roughly. */
if (!out) return 0;
