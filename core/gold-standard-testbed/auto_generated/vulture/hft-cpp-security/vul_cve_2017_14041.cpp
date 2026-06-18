// Vulnerable: VUL-CVE-2017-14041
fseek(f, 0, SEEK_SET);
if (fscanf(f, "PG%[ \t]%c%c%[ \t+-]%d%[ \t]%d%[ \t]%d", temp, &endian1,
           &endian2, signtmp, &prec, temp, &w, temp, &h) != 9) {
    fclose(f);
