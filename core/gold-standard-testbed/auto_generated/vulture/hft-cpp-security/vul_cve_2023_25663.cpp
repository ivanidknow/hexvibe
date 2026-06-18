// Vulnerable: VUL-CVE-2023-25663
ResourceMgr* rm = ctx->resource_manager();
    if (rm == nullptr) return errors::Internal("No resource manager.");
    TF_RETURN_IF_ERROR(
        ctx->step_container()->Lookup(rm, container + ta_handle, tensor_array));
    return OkStatus();
  } else {
// --- tensor_array_ops_test.py ---
    self.assertEqual([42, 1], ta.stack().shape.as_list())


class TensorArrayBenchmark(test.Benchmark):
