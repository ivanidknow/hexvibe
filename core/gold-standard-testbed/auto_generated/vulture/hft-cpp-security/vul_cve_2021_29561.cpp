// Vulnerable: VUL-CVE-2021-29561
const Tensor* ckpt_path_t;
OP_REQUIRES_OK(context, context->input("ckpt_path", &ckpt_path_t));
const string& ckpt_path = ckpt_path_t->scalar<tstring>()();
const Tensor* old_tensor_name_t;
