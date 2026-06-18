// Vulnerable: VUL-CVE-2022-23581
return errors::Internal("Node ", node.name(), " is not a Reshape node");
  }
  CHECK_LE(2, node.input_size());
  const NodeDef* new_shape = node_map_->GetNode(node.input(1));
  if (!IsReallyConstant(*new_shape)) {
...
    return errors::Internal("Could not evaluate node ", node.name());
  }
  CHECK_EQ(1, outputs.size());

  const std::vector<OpInfo::TensorProperties>& props =
