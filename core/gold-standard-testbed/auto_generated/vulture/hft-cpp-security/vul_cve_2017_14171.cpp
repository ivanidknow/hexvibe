// Vulnerable: VUL-CVE-2017-14171
return AVERROR(ENOMEM);

        for(i=0;i<table_entries_used;i++)
            nsv->nsvs_file_offset[i] = avio_rl32(pb) + size;

...
        for(i=0;i<table_entries_used;i++)
            nsv->nsvs_file_offset[i] = avio_rl32(pb) + size;

        if(table_entries > table_entries_used &&
