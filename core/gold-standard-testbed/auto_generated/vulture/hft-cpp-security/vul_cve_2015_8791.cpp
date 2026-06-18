// Vulnerable: VUL-CVE-2015-8791
2015-10-20  Moritz Bunkus  <moritz@bunkus.org>

        * EbmlUnicodeString::UpdateFromUTF8(): Fixed an invalid memory
// --- EbmlElement.cpp ---
      PossibleSizeLength = SizeIdx + 1;
      SizeBitMask >>= SizeIdx;
      for (SizeIdx = 0; SizeIdx < PossibleSizeLength; SizeIdx++) {
        PossibleSize[SizeIdx] = InBuffer[SizeIdx];
