// Vulnerable: VUL-CVE-2015-8790
2015-10-17  Moritz Bunkus  <moritz@bunkus.org>
// --- EbmlUnicodeString.cpp ---
// ===================== UTFstring class ===================

UTFstring::UTFstring()
...
  // find the size of the final UCS-2 string
  size_t i;
  for (_Length=0, i=0; i<UTF8string.length(); _Length++) {
    uint8 lead = static_cast<uint8>(UTF8string[i]);
    if (lead < 0x80)
...
      break;
  }
  _Data[j] = 0;
