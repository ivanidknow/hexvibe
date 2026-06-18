// Vulnerable: VUL-CVE-2023-24751
const PBMotion& vi = img->get_mv_info(xB[k],yB[k]);

        if (vi.predFlag[X]==1 &&
            shdr->LongTermRefPic[X][refIdxLX] == shdr->LongTermRefPic[X][ vi.refIdx[X] ]) {
...
        out_vi->refIdx[l] = motion.refIdx[l];
        out_vi->predFlag[l] = 1;
      }
      else {
