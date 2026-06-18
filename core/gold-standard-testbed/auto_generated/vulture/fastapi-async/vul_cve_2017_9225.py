# Vulnerable: VUL-CVE-2017-9225
r = re.sub(REG_GET_CODE, 'OnigCodePoint gcode = wordlist[key].code;', s)
    if r != s: return r
    r = re.sub(REG_CODE_CHECK, 'if (code == gcode)', s)
    if r != s: return r
// --- unicode_unfold_key.c ---
          OnigCodePoint gcode = wordlist[key].code;

          if (code == gcode)
            return &wordlist[key];
        }
