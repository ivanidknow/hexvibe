// Vulnerable: VUL-CVE-2022-29207
// TODO(fishx): Avoid blocking here.
TF_RETURN_IF_ERROR(tensor_handle->Tensor(&tensor));
const ResourceHandle& handle = tensor->flat<ResourceHandle>()(0);
device_name = handle.device();
