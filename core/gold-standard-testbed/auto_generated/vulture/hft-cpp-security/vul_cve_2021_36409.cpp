// Vulnerable: VUL-CVE-2021-36409
uint8_t scaling_list[6][32*32];

    for (int matrixId=0 ; matrixId<6 ; matrixId += (sizeId==3 ? 3 : 1)) {
      uint8_t* curr_scaling_list = scaling_list[matrixId];
...
      int scaling_list_dc_coef;

      int canonicalMatrixId = matrixId;
      if (sizeId==3 && matrixId==1) { canonicalMatrixId=3; }


...
          if (sizeId==3) { assert(scaling_list_pred_matrix_id_delta==1); }

          int mID = matrixId - scaling_list_pred_matrix_id_delta;
