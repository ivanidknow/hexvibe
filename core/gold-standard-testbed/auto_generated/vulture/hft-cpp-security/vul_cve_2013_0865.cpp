// Vulnerable: VUL-CVE-2013-0865
chunk_size = bytestream2_get_be32(&s->gb);

        /* accumulate partial codebook */
        bytestream2_get_buffer(&s->gb, &s->next_codebook_buffer[s->next_codebook_buffer_index],
...
        bytestream2_seek(&s->gb, cbpz_chunk, SEEK_SET);
        chunk_size = bytestream2_get_be32(&s->gb);

        /* accumulate partial codebook */
