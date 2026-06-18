// Vulnerable: VUL-CVE-2021-29567
values_t->shape().DebugString(), " and ",
                shape_t->shape().DebugString()));

const auto indices_mat = indices_t->matrix<int64>();
