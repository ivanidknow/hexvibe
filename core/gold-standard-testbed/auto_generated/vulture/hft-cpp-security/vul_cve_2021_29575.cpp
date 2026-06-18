// Vulnerable: VUL-CVE-2021-29575
OP_REQUIRES_OK(context, context->GetAttr("batch_dim", &batch_dim_));
  OP_REQUIRES_OK(context, context->GetAttr("seq_dim", &seq_dim_));
}
