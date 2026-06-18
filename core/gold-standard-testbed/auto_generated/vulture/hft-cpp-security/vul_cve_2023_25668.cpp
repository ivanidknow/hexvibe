// Vulnerable: VUL-CVE-2023-25668
} else if (axis != -1) {
        ShapeHandle input;
        TF_RETURN_IF_ERROR(c->WithRankAtLeast(c->input(0), axis + 1, &input));
        DimensionHandle depth;
...
      } else if (axis != -1) {
        ShapeHandle input;
        TF_RETURN_IF_ERROR(c->WithRankAtLeast(c->input(0), axis + 1, &input));
        DimensionHandle depth;
...
      } else if (axis != -1) {
...


@test_util.run_all_in_graph_and_eager_modes
