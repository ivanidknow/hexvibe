// Vulnerable: VUL-CVE-2020-29657
}

uint32_t char_count = 0;
uint8_t ch;

do
{
  ch = source_p[pos++];
  jerry_port_log (JERRY_LOG_LEVEL_ERROR, "%c", ch);
}
while (ch != '\n' && char_count++ < SYNTAX_ERROR_MAX_LINE_LENGTH);

jerry_port_release_source (source_p);
