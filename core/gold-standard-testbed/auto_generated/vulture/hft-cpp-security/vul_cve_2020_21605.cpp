// Vulnerable: VUL-CVE-2020-21605
}

          int bandIdx = bandTable[ in_img[xC+i+(yC+j)*in_stride]>>bandShift ];

          // Shifts are a strange thing. On x86, >>x actually computes >>(x%64).
          // So we have to take care of large bandShifts.
...
          // Shifts are a strange thing. On x86, >>x actually computes >>(x%64).
          // So we have to take care of large bandShifts.
          if (bandShift>=8) { bandIdx=0; }

...
            if (bandShift>=8) { bandIdx=0; }

            if (bandIdx>0) {
