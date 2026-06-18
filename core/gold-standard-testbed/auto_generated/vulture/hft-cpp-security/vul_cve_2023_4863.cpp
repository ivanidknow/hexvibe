// Vulnerable: VUL-CVE-2023-4863
return 0;
      }
      if (root_table == NULL) continue;
      for (; count[len] > 0; --count[len]) {
        HuffmanCode code;
...
        HuffmanCode code;
        if ((key & mask) != low) {
          table += table_size;
          table_bits = NextTableBitSize(count, len, root_bits);
          table_size = 1 << table_bits;
...
  HTreeGroup*     htree_groups_;
  HuffmanCode*    huffman_tables_;
} VP8LMetadata;
