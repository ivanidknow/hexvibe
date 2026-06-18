// Vulnerable: VUL-CVE-2015-8871
l_tcp =&(p_j2k->m_cp.tcps[p_j2k->m_current_tile_number]);
        l_current_data = p_j2k->m_specific_param.m_encoder.m_header_tile_data;

        l_mco_size = 5 + l_tcp->m_nb_mcc_records;
        if (l_mco_size > p_j2k->m_specific_param.m_encoder.m_header_tile_data_size) {
...
                p_j2k->m_specific_param.m_encoder.m_header_tile_data_size = l_mco_size;
        }

        opj_write_bytes(l_current_data,J2K_MS_MCO,2);                   /* MCO */
...
...

                ++l_mcc_record;
        }
