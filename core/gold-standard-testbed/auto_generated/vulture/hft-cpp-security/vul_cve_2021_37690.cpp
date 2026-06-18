// Vulnerable: VUL-CVE-2021-37690
outer_context->set_output(index, handle);

    auto* resource = node_context->input_handle_shapes_and_types(0);
    if (resource) {
      outer_context->set_output_handle_shapes_and_types(index, *resource);
...
    auto* resource = node_context->input_handle_shapes_and_types(0);
    if (resource) {
      outer_context->set_output_handle_shapes_and_types(index, *resource);
    }
  }
