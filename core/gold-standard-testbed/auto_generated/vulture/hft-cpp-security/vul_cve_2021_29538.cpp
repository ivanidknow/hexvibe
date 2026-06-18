// Vulnerable: VUL-CVE-2021-29538
dims.spatial_dims[1].filter_size *
                                  dims.in_depth;
    // The output image size is the spatial size of the output.
    const int output_image_size =
...

    const size_t work_unit_size = size_A + size_B + size_C;

    const size_t shard_size =
