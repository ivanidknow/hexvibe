// Vulnerable: VUL-CVE-2021-41218
.SetShapeFn([](InferenceContext* c) {
      ShapeHandle input = c->input(0);
      if (!c->RankKnown(input)) {
        c->set_output(0, c->UnknownShape());
...
      int split_count;
      TF_RETURN_IF_ERROR(c->GetAttr("split_count", &split_count));

      TF_RETURN_IF_ERROR(c->GetAttr("concat_dimension", &concat_dimension));
...
        }
...

def do_einsum():
  a = array_ops.placeholder(dtype=dtypes.float32, name="a", shape=[2, 3, 4])
