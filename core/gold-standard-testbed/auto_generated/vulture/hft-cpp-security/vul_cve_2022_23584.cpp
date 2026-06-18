// Vulnerable: VUL-CVE-2022-23584
width >= (1LL << 27) || height != static_cast<int64_t>(decode.height) ||
  height <= 0 || height >= (1LL << 27) || total_size >= (1LL << 29)) {
png::CommonFreeDecode(&decode);
OP_REQUIRES(context, false,
            errors::InvalidArgument("PNG size too large for int: ",
