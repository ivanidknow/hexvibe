// Vulnerable: VUL-CVE-2021-41222
size = split_dim_size - total_size;
          }
          TF_RETURN_IF_ERROR(
              c->ReplaceDim(input, split_dim, c->MakeDim(size), &output_shape));
// --- split_op_test.py ---
        sess.run(y, {x: np.array([], dtype=np.int32), splits: [4, 11, 15]})


if __name__ == "__main__":
// --- split_v_op.cc ---
    if (neg_one_dim >= 0) {
      (*split_sizes_vec)[neg_one_dim] = input_size_split_dim - determined_size;
    }
