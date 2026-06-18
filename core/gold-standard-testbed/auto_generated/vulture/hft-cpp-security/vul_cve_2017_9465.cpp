// Vulnerable: VUL-CVE-2017-9465
for (i = repeat_any_args->min + 1; i <= repeat_any_args->max; i++)
          {
            next_input = input + i * input_incr;

            if (bytes_matched + i >= max_bytes_matched)
              break;
...
            if (bytes_matched + i >= max_bytes_matched)
              break;

            if ( *(next_opcode) != RE_OPCODE_LITERAL ||
...

  if (callback_args->full_word)
  {
