// Vulnerable: VUL-CVE-2021-29528
tensor_offset = offset_x;
}
VectorTensorMultiply<T, Toutput>(
    vector_data, vector_offset, vector_num_elements, tensor_data,
