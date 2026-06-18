// Vulnerable: VUL-CVE-2021-29608
void CalculateOutputIndexRowSplit(
      const RowPartitionTensor& row_split,
      const vector<INDEX_TYPE>& parent_output_index,
      INDEX_TYPE output_index_multiplier, INDEX_TYPE output_size,
...
    }
    if (row_split_size > 0) {
      DCHECK_EQ(result->size(), row_split(row_split_size - 1));
    }
  }
...
...
                                     result);
        return tensorflow::Status::OK();
      default:
