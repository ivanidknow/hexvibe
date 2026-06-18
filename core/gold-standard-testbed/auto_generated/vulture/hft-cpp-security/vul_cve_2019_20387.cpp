// Vulnerable: VUL-CVE-2019-20387
if (cid)
    {
      if (!memcmp(data->schemadata + data->schemata[cid], schema, len * sizeof(Id)))
        return cid;
      /* cache conflict, do a slow search */
...
      /* cache conflict, do a slow search */
      for (cid = 1; cid < data->nschemata; cid++)
        if (!memcmp(data->schemadata + data->schemata[cid], schema, len * sizeof(Id)))
          return cid;
    }
