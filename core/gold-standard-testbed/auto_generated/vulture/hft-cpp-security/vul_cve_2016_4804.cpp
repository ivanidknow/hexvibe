// Vulnerable: VUL-CVE-2016-4804
(unsigned long long)fs->fat_start / lss);
    printf("%10d FATs, %d bit entries\n", b->fats, fs->fat_bits);
    printf("%10d bytes per FAT (= %u sectors)\n", fs->fat_size,
	   fs->fat_size / lss);
    if (!fs->root_cluster) {
	printf("Root directory starts at byte %llu (sector %llu)\n",
...
    unsigned total_sectors;
    unsigned short logical_sector_size, sectors;
    unsigned fat_length;
    unsigned total_fat_entries;
...
    unsigned int fat_size;	/* unit is bytes */
    unsigned int fat_bits;	/* size of a FAT entry */
    unsigned int eff_fat_bits;	/* # of used bits in a FAT entry */
