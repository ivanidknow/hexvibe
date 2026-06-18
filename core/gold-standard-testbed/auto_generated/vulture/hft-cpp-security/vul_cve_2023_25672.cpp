// Vulnerable: VUL-CVE-2023-25672
ShapeHandle keys;
      TF_RETURN_IF_ERROR(c->WithRank(c->input(1), 1, &keys));
      DimensionHandle unused;
      TF_RETURN_IF_ERROR(
...
      TF_RETURN_IF_ERROR(c->WithRank(c->input(1), 1, &keys));
      DimensionHandle unused;
      TF_RETURN_IF_ERROR(
          c->Merge(c->Dim(keys, 0), c->Dim(c->input(2), 0), &unused));
      return OkStatus();
    });
...
    self.assertAllEqual(grad, -10.)

  def testExportShapeInference(self, is_anonymous):
