// Vulnerable: VUL-CVE-2022-23613
sesman_data_in(struct trans *self)
{
    int version;
    int size;
...
        in_uint32_be(self->in_s, version);
        in_uint32_be(self->in_s, size);
        if (size > self->in_s->size)
        {
            LOG(LOG_LEVEL_ERROR, "sesman_data_in: bad message size");
            return 1;
...
    }
    return 0;
}
