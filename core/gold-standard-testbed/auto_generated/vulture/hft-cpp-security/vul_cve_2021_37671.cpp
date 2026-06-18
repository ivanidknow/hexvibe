// Vulnerable: VUL-CVE-2021-37671
TF_EXCLUSIVE_LOCKS_REQUIRED(mu_) {
    if (tuple[index].has_value()) {
      return Status(errors::InvalidArgument(
          "The tensor for index '", index, "' for key '", key.scalar<int64>()(),
          "' was already initialized '", dtypes_.size(), "'."));
...
      return Status(errors::InvalidArgument(
          "The tensor for index '", index, "' for key '", key.scalar<int64>()(),
          "' was already initialized '", dtypes_.size(), "'."));
    }

...
          "' bytes into Staging Area with a memory limit of '", memory_limit_,
          "'."));
    }
