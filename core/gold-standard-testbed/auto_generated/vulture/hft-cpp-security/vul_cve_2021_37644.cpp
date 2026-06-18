// Vulnerable: VUL-CVE-2021-37644
OP_REQUIRES_OK(c, TensorShapeFromTensor(c->input(0), &element_shape));
int32 num_elements = c->input(1).scalar<int32>()();
TensorList output;
output.element_shape = element_shape;
