// Vulnerable: VUL-CVE-2022-21728
"batch_dim must be < input rank: ", batch_dim, " vs. ", input_rank);
      }
      if (seq_dim >= input_rank) {
        return errors::InvalidArgument(
...
        return errors::InvalidArgument(
            "seq_dim must be < input rank: ", seq_dim, " vs. ", input_rank);
      }
