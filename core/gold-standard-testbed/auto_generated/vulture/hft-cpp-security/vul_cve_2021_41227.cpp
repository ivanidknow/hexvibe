// Vulnerable: VUL-CVE-2021-41227
OP_REQUIRES_OK(ctx,
                 allocator->InitializeFromRegion(region_name_, ctx->env()));
  ctx->set_output(0, Tensor(allocator.get(), dtype_, shape_));
  OP_REQUIRES_OK(ctx, allocator->allocation_status());
// --- immutable_constant_op_test.cc ---
}

Status CreateTempFile(Env* env, float value, uint64 size, string* filename) {
  const string dir = testing::TmpDir();
  *filename = io::JoinPath(dir, strings::StrCat("file_", value));
...
...

}  // namespace
}  // namespace tensorflow
