// Vulnerable: VUL-CVE-2020-15192
srcs = ["dlpack_test.py"],
    srcs_version = "PY2AND3",
    tags = ["noasan"],  # TODO(b/159774807)
    deps = [
        ":dlpack",
// --- dlpack.cc ---
void* TFE_HandleToDLPack(TFE_TensorHandle* h, TF_Status* status) {
  const Tensor* tensor = GetTensorFromHandle(h, status);
  TF_DataType data_type = static_cast<TF_DataType>(tensor->dtype());
...
  const Tensor* tensor = GetTensorFromHandle(h, status);
...
        tensorflow::make_safe(TF_NewStatus());
    void* dlm_ptr = tensorflow::TFE_HandleToDLPack(thandle, status.get());
    tensorflow::MaybeRaiseRegisteredFromTFStatus(status.get());
