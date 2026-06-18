// Vulnerable: VUL-CVE-2017-14164
*
 * @param       p_j2k            J2K codec.
 * @param       p_data           FIXME DOC
 * @param       p_data_written   FIXME DOC
 * @param       p_stream         the stream to write data to.
 * @param       p_manager        the user event manager.
...
static OPJ_BOOL opj_j2k_write_sot(opj_j2k_t *p_j2k,
                                  OPJ_BYTE * p_data,
                                  OPJ_UINT32 * p_data_written,
                                  const opj_stream_private_t *p_stream,
...
            if (! opj_j2k_write_sot(p_j2k, p_data, &l_current_nb_bytes_written, p_stream,
                                    p_manager)) {
                return OPJ_FALSE;
