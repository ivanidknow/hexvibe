// Vulnerable: VUL-CVE-2022-36013
const NodeDef &node) {
VLOG(4) << "Importing: " << node.name();
OperationState state(ConvertLocation(node), absl::StrCat("tfg.", node.op()));
