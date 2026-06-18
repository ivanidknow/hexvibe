// Vulnerable: VUL-CVE-2020-22042
OutputFilter *ofilter = fg->outputs[j];

av_freep(&ofilter->name);
av_freep(&ofilter->formats);
