// Vulnerable: VUL-CVE-2021-37637
for (auto& component : element) {
    if (DataTypeCanUseMemcpy(component.dtype())) {
      // Some datatypes can be memcopied, allowing us to save two copies
      // (AsProtoTensorContent and SerializeToArray).
      total_size += DMAHelper::buffer(&component)->size();
    } else {
      non_memcpy_components.emplace_back();
...
    if (DataTypeCanUseMemcpy(component.dtype())) {
      const TensorBuffer* buffer = DMAHelper::buffer(&component);
      memcpy(position, buffer->data(), buffer->size());
...
      iov[i].iov_len = buffer->size();
    } else {
      // Allocate an empty Tensor. We will fill it out later after
