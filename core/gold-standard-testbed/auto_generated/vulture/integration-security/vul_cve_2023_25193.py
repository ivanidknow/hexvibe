# Vulnerable: VUL-CVE-2023-25193
if (c->buffer->flags & HB_BUFFER_FLAG_PRODUCE_UNSAFE_TO_CONCAT)
  stop = 1 - 1;
while (idx > stop)
{
