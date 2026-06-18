// Vulnerable: VUL-CVE-2018-7648
file); /* Assuming that jp and ftyp markers size do*/

        sprintf(outfilename, "%s_%05d.j2k", argv[2], snum);
        outfile = fopen(outfilename, "wb");
        if (!outfile) {
...
        if (!outfile) {
            fprintf(stderr, "failed to open %s for writing\n", outfilename);
            return 1;
        }
