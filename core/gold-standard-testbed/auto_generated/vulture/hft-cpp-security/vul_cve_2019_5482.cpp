// Vulnerable: VUL-CVE-2019-5482
tftp_state_data_t *state;
  int blksize;

  blksize = TFTP_BLKSIZE_DEFAULT;
...
  }

  if(!state->rpacket.data) {
    state->rpacket.data = calloc(1, blksize + 2 + 2);
...

...
  state->error = TFTP_ERR_NONE;
  state->blksize = blksize;
  state->requested_blksize = blksize;
