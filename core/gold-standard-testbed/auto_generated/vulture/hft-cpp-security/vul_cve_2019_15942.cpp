// Vulnerable: VUL-CVE-2019-15942
static void alloc_rbsp_buffer(H2645RBSP *rbsp, unsigned int size, int use_ref)
{
    if (size > INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE)
        goto fail;
...

    if (rbsp->rbsp_buffer_alloc_size >= size &&
        (!rbsp->rbsp_buffer_ref || av_buffer_is_writable(rbsp->rbsp_buffer_ref)))
        return;

...
...
    rbsp->rbsp_buffer = av_malloc(size);
    if (!rbsp->rbsp_buffer)
        goto fail;
