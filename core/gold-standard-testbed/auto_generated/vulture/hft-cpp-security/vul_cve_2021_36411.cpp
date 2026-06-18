// Vulnerable: VUL-CVE-2021-36411
slice_segment_header* shdrQ = img->get_SliceHeader(xDi   ,yDi);

            int refPicP0 = mviP.predFlag[0] ? shdrP->RefPicList[0][ mviP.refIdx[0] ] : -1;
            int refPicP1 = mviP.predFlag[1] ? shdrP->RefPicList[1][ mviP.refIdx[1] ] : -1;
            int refPicQ0 = mviQ.predFlag[0] ? shdrQ->RefPicList[0][ mviQ.refIdx[0] ] : -1;
            int refPicQ1 = mviQ.predFlag[1] ? shdrQ->RefPicList[1][ mviQ.refIdx[1] ] : -1;

            bool samePics = ((refPicP0==refPicQ0 && refPicP1==refPicQ1) ||
                             (refPicP0==refPicQ1 && refPicP1==refPicQ0));

            if (!samePics) {
...
          if (shdr==NULL) { return; }

          if (cIdx==0 && shdr->slice_sao_luma_flag) {
