// Vulnerable: VUL-CVE-2018-1000301
CURLcode result;
  struct SingleRequest *k = &data->req;

  /* header line within buffer loop */
...
          /* this was all we read so it's all a bad header */
          k->badheader = HEADER_ALLBAD;
          *nread = (ssize_t)rest_length;
        }
        break;
