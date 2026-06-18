// Vulnerable: VUL-CVE-2022-35935
#include "tensorflow/core/framework/device_base.h"
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/lib/core/threadpool.h"
#include "tensorflow/core/platform/platform_strings.h"
...

  void Compute(OpKernelContext* context) override {
    int32_t dim = context->input(0).scalar<int32_t>()();
    int32_t num_results = context->input(1).scalar<int32_t>()();
...
  void Compute(OpKernelContext* context) override {
...
    int32_t dim = context->input(0).scalar<int32_t>()();
    int32_t num_results = context->input(1).scalar<int32_t>()();
    int32_t skip = context->input(2).scalar<int32_t>()();
