// Vulnerable: VUL-CVE-2022-41900
errors::InvalidArgument(
                    "pooling_ratio field must specify 4 dimensions"));
    OP_REQUIRES(
        context, pooling_ratio_[0] == 1 || pooling_ratio_[3] == 1,
...
      input_size[i] = tensor_in.dim_size(i);
      OP_REQUIRES(
          context, pooling_ratio_[i] <= input_size[i],
          errors::InvalidArgument(
              "Pooling ratio cannot be bigger than input tensor dim size."));
    }
...
            seed2=0,
            name=None)
        self.evaluate(result)
