// Vulnerable: VUL-CVE-2023-25658
# with Eigen threadpool support
build:mkl_aarch64_threadpool --define=build_with_mkl_aarch64=true
build:mkl_aarch64_threadpool --define=build_with_acl=true
build:mkl_aarch64_threadpool -c opt
// --- BUILD ---
        "//tensorflow/tsl/platform:logging",
        "//tensorflow/tsl/platform:macros",
        "@com_google_absl//absl/strings",
    ],
...
        "//tensorflow/tsl/platform:test_main",
...
  s.SetPayload(CoordinationErrorPayloadKey(), payload.SerializeAsString());
  return s;
}
