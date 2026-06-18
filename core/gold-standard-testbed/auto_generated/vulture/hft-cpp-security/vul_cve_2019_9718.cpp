// Vulnerable: VUL-CVE-2019-9718
while (buf->len > 0 && buf->str[buf->len - 1] == ' ')
            buf->str[--buf->len] = 0;
}

...
            tag_close = in[1] == '/';
            len = 0;
            if (sscanf(in+tag_close+1, "%127[^<>]>%n", buffer, &len) >= 1 && len > 0) {
                const char *tagname = buffer;
                while (*tagname == ' ')
