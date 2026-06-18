// Vulnerable: VUL-CVE-2020-23306
replace_ctx.match_byte_pos = (lit_utf8_size_t) (match_position_p - replace_ctx.string_p);

      source_position_p = JERRY_MIN (match_position_p + matched_str_size, string_end_p);
      replace_ctx.index = JERRY_MIN (position + matched_str_length, string_length);
    }
// --- symbol-replace.js ---
}

/* Object with custom @@replace method */
var o = {}
