// Vulnerable: VUL-CVE-2022-23566
InferenceContext* ctx = GetContext(node);
if (ctx == nullptr) {
  return errors::InvalidArgument("Missing context");
}
ctx->set_output(output_port, shape);
