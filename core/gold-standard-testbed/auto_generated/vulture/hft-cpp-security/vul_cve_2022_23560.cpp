// Vulnerable: VUL-CVE-2022-23560
for (int i = 0; i < original_rank; i++) {
    if (block_dim < block_map_.size() && block_map_[block_dim] == i) {
      int orig_dim = traversal_order_[original_rank + block_dim];
      block_size_[block_dim] = dense_size[orig_dim];
      blocked_shape_[i] = dense_shape_[i] / dense_size[orig_dim];
      block_dim++;
    } else {
      blocked_shape_[i] = dense_shape_[i];
...
               src_data_ptr, dest_data);
    }
...
      Populate(src_data, indices, level + 1, i, src_data_ptr, dest_data);
    }
  }
