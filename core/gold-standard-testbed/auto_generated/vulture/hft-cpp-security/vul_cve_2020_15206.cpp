// Vulnerable: VUL-CVE-2020-15206
#include "tensorflow/cc/saved_model/reader.h"
#include "tensorflow/core/framework/attr_value.pb.h"
#include "tensorflow/core/framework/node_def.pb.h"
#include "tensorflow/core/framework/tensor.pb.h"
...
// Also ensure that constant nodes have a value assigned to them.
// TODO(b/154763635): this is temporary and will be replaced with a better audit
static Status ValidateSavedTensors(const GraphDef& graph_def) {
  for (const auto& node : graph_def.node()) {
...
static Status ValidateSavedTensors(const GraphDef& graph_def) {
...

}  // namespace
}  // namespace tensorflow
