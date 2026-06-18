// Vulnerable: VUL-CVE-2021-41221
.Attr("is_training: bool = true")
    .SetShapeFn([](InferenceContext* c) {
      auto input_shape = c->input(0);
      auto input_h_shape = c->input(1);
      auto seq_length = c->Dim(input_shape, 0);
      auto batch_size = c->Dim(input_shape, 1);
...
      auto batch_size = c->Dim(input_shape, 1);
      auto num_units = c->Dim(input_h_shape, 2);
      string direction;
      TF_RETURN_IF_ERROR(c->GetAttr("direction", &direction));
...
                   .Finalize(&op.node_def));
  INFER_OK(op, input_shapes_desc, output_shapes_desc);
}
