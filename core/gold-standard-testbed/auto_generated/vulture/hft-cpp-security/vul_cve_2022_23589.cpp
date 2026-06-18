// Vulnerable: VUL-CVE-2022-23589
NodeDef* input_node = graph.GetNode(tensor_id.node());
  return IsSwitch(*input_node);
}
