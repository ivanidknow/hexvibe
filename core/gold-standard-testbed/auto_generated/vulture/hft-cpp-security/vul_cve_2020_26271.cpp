// Vulnerable: VUL-CVE-2020-26271
#include "tensorflow/core/lib/strings/scanner.h"
#include "tensorflow/core/lib/strings/str_util.h"
#include "tensorflow/core/platform/logging.h"
#include "tensorflow/core/platform/macros.h"
...
Status GraphConstructor::MakeEdge(Node* src, int output_index, Node* dst,
                                  int input_index) {
  DataType src_out = src->output_type(output_index);
  DataType dst_in = dst->input_type(input_index);
