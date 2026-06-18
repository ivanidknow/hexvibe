# Vulnerable: VUL-CVE-2022-41883
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
...
      self.assertAllEqual(7.0 * self.evaluate(datum), grad)


if __name__ == "__main__":
// --- execute.cc ---
  const OpDef& op_def = OpRegistry::Global()->LookUp(op.Name())->op_def;
  const int arg_id = OpPortIdToArgId(*node_def, op_def.input_arg(), port_id);
  return std::find(host_memory_args.begin(), host_memory_args.end(),
                   op_def.input_arg(arg_id).name()) != host_memory_args.end();
