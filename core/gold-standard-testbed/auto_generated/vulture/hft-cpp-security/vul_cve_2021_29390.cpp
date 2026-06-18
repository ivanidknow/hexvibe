// Vulnerable: VUL-CVE-2021-29390
2.0.90 (2.1 beta1)
==================
// --- jdcoefct.c ---
          DC24 = (int)next_next_block_row[1][0];
        }
        if (block_num < last_block_column - 1) {
          DC05 = (int)prev_prev_block_row[2][0];
          DC10 = (int)prev_block_row[2][0];
