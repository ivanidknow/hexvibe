// Vulnerable: VUL-CVE-2021-41205
TF_RETURN_IF_ERROR(c->WithRank(c->input(1), minmax_rank, &minmax));
      TF_RETURN_IF_ERROR(c->Merge(c->input(2), minmax, &minmax));
      if (axis != -1) {
        ShapeHandle input;
        TF_RETURN_IF_ERROR(c->WithRankAtLeast(c->input(0), axis + 1, &input));
...
      TF_RETURN_IF_ERROR(c->WithRank(c->input(1), minmax_rank, &minmax));
      TF_RETURN_IF_ERROR(c->Merge(c->input(2), minmax, &minmax));
      if (axis != -1) {
        ShapeHandle input;
        TF_RETURN_IF_ERROR(c->WithRankAtLeast(c->input(0), axis + 1, &input));
...
              "[1,2,?,4,5];[];[1]");
  INFER_ERROR("Shape must be rank 0 but is rank 1", op, "[1,2,?,4,5];[1];[1]");
}
