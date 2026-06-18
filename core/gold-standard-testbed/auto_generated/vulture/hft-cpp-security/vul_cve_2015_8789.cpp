// Vulnerable: VUL-CVE-2015-8789
2015-10-20  Moritz Bunkus  <moritz@bunkus.org>

        * EbmlElement::ReadCodedSizeValue(): Fixed an invalid memory
// --- EbmlMaster.cpp ---
          if (DeleteElement)
            delete ElementLevelA;
          break;
        }
