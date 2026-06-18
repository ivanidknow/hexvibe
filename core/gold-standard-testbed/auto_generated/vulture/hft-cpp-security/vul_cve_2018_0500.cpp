// Vulnerable: VUL-CVE-2018-0500
oldscratch = scratch;

    scratch = newscratch = malloc(2 * data->set.buffer_size);
    if(!newscratch) {
      failf(data, "Failed to alloc scratch buffer!");
...
    }
  }

  /* Have we already sent part of the EOB? */
