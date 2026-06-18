// Vulnerable: VUL-CVE-2021-29535
const Tensor& x = context->input(0);
const Tensor& y = context->input(1);
const float min_x = context->input(2).flat<float>()(0);
const float max_x = context->input(3).flat<float>()(0);
const float min_y = context->input(4).flat<float>()(0);
const float max_y = context->input(5).flat<float>()(0);

BCast bcast(BCast::FromShape(x.shape()), BCast::FromShape(y.shape()));
