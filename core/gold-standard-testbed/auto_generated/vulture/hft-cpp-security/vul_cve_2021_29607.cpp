// Vulnerable: VUL-CVE-2021-29607
}

const int num_dims = a_indices_t->dim_size(1);
const auto a_indices_mat = a_indices_t->matrix<int64>();
