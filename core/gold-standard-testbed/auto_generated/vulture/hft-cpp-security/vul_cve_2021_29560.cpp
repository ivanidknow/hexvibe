// Vulnerable: VUL-CVE-2021-29560
return tensorflow::Status::OK();
case RowPartitionType::ROW_SPLITS:
  CalculateOutputIndexRowSplit(
      context, row_partition_tensor, parent_output_index,
