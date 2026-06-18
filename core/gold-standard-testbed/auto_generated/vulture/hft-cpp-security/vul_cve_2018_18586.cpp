// Vulnerable: VUL-CVE-2018-18586
2018-10-17  Stuart Caie <kyzer@cabextract.org.uk>
// --- chmextract.c ---
mode_t user_umask;

#define FILENAME ".test.chmx"

/**
 * Ensures that all directory components in a filepath exist. New directory
...
}

...
	    char *outname = create_output_name((unsigned char *)f[i]->filename,NULL,0,1,0);
	    printf("Extracting %s\n", outname);
	    ensure_filepath(outname);
