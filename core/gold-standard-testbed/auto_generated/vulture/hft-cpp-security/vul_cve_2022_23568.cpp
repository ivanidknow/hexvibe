// Vulnerable: VUL-CVE-2022-23568
auto input_shape_vec = input_shape->vec<int64_t>();
    int new_num_elements = 1;
    bool overflow_ocurred = false;
    for (int i = 0; i < input_shape_vec.size(); i++) {
      new_num_elements =
          MultiplyWithoutOverflow(new_num_elements, input_shape_vec(i));
      if (new_num_elements < 0) {
        overflow_ocurred = true;
        break;
      }
    }
...
    TensorShape tensor_input_shape(input_shape_vec);
    gtl::InlinedVector<int64_t, 8> std_order(rank);
    std::iota(std_order.begin(), std_order.end(), 0);
