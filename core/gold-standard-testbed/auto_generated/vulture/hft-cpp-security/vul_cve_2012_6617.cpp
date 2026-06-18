// Vulnerable: VUL-CVE-2012-6617
AVFormatContext *avc;
    AVStream *avs = NULL;
    int i;

...

    avc =  avformat_alloc_context();
    if (avc == NULL) {
        return -1;
    }
...
...
    }
    av_dict_set(&avc->metadata, "title",
               stream->title[0] ? stream->title : "No Title", 0);
