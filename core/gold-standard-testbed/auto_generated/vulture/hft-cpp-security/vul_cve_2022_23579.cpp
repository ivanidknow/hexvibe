// Vulnerable: VUL-CVE-2022-23579
const NodeDef* input = node_map_->GetNode(NodeName(node.input(0)));
CHECK(input != nullptr) << "node = " << node.name()
                        << " input = " << node.input(0);
// Don't remove Identity nodes corresponding to Variable reads or following
// Recv.
