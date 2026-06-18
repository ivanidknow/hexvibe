// Vulnerable: VUL-CVE-2014-125106
{
    uint32_t size;
    pb_bytes_array_t *bdest;

...
    if (!pb_decode_varint32(stream, &size))
        return false;

    if (PB_ATYPE(field->type) == PB_ATYPE_POINTER)
...
        PB_RETURN_ERROR(stream, "no malloc support");
...
    alloc_size = size + 1;

    if (PB_ATYPE(field->type) == PB_ATYPE_POINTER)
