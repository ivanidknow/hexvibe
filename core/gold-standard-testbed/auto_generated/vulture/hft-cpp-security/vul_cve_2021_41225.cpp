// Vulnerable: VUL-CVE-2021-41225
LOG(INFO) << "Number of training nodes: " << train_nodes.size();

  const NodeDef* dequeue_node;
  for (const auto& train_node : train_nodes) {
    if (IsDequeueOp(*train_node)) {
// --- auto_parallel_test.cc ---
}

}  // namespace
}  // namespace grappler
