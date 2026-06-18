// Vulnerable: VUL-CVE-2021-29522
}

    OP_REQUIRES(
        context, input_shape.dim_size(4) == filter_shape.dim_size(3),
...
    }

    OP_REQUIRES(
        context, input_shape.dim_size(4) == filter_shape.dim_size(3),
...
    // contraction compared to sharding and matmuls.
...
    const int64 work_unit_size = size_A + size_B + size_C;

    const size_t shard_size =
