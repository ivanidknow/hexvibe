// Vulnerable: VUL-CVE-2020-15209
":external_cpu_backend_context",
        ":graph_info",
        ":memory_planner",
        ":minimal_logging",
...
        "testdata/empty_model.bin",
        "testdata/multi_add_flex.bin",
        "testdata/sparse_tensor.bin",
        "testdata/test_min_runtime.bin",
// --- model_test.cc ---
// TODO(b/150072943): Add malformed model with sparse tensor tests.
...
        TF_LITE_ENSURE_STATUS(EnsureTensorDataIsReadable(tensor_index));
      }
    }
