// Vulnerable: VUL-CVE-2021-29616
Status TrySimplify(NodeDef* consumer, string* simplified_node_name) override {
    NodeDef* producer;
    TF_RETURN_IF_ERROR(GetInputNode(consumer->input(0), &producer));
    const bool producer_is_cast = IsCastLike(*producer);
...

  bool IsSupported(const NodeDef* node) const override {
    return IsAnyMul(*node) && node->input(0) == node->input(1);
  }
// --- dependency_optimizer.cc ---
    return false;
  }
  const NodeDef* input = node_map_->GetNode(NodeName(node.input(0)));
  CHECK(input != nullptr) << "node = " << node.name()
