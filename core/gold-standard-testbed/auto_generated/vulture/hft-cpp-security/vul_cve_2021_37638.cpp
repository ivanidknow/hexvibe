// Vulnerable: VUL-CVE-2021-37638
const Tensor first_partition_tensor =
    context->input(kFirstPartitionInputIndex);
const RowPartitionType first_partition_type = row_partition_types_[0];
switch (first_partition_type) {
