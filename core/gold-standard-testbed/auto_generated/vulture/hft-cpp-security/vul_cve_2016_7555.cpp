// Vulnerable: VUL-CVE-2016-7555
av_freep(&s->streams[0]->codecpar->extradata);
                av_freep(&s->streams[0]->codecpar);
                if (s->streams[0]->info)
                    av_freep(&s->streams[0]->info->duration_error);
...
                    av_freep(&s->streams[0]->info->duration_error);
                av_freep(&s->streams[0]->info);
                av_freep(&s->streams[0]);
                s->nb_streams = 0;
