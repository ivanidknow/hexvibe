// Vulnerable: VUL-CVE-2022-23587
// out cost per box from cost per pixel and cost per element.

  // Ops for variables height_scale and width_scale.
  int64_t ops = (sub_cost * 6 + mul_cost * 2 + div_cost * 2) * num_boxes;
...
  int64_t ops = (sub_cost * 6 + mul_cost * 2 + div_cost * 2) * num_boxes;
  // Ops for variable in_y.
  ops += (mul_cost * 2 + sub_cost + add_cost) * crop_height * num_boxes;
  // Ops for variable in_x (same computation across both branches).
  ops += (mul_cost * 2 + sub_cost + add_cost) * crop_height * crop_width *
...
...
    ops += round_cost * 2 * crop_height * crop_width * num_boxes;
    // Ops for innermost loop across depth.
    ops += cast_to_float_cost * output_elements;
