// Vulnerable: VUL-CVE-2015-8872
} else {
    FAT_ENTRY subseqEntry;
    if (cluster != fs->clusters - 1)
	get_fat(&subseqEntry, fs->fat, cluster + 1, fs);
    else
