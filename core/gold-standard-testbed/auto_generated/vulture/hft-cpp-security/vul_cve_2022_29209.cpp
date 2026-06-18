// Vulnerable: VUL-CVE-2022-29209
struct Voidifier {
  template <typename T>
  void operator&(const T&)const {}
};

...

// Helper functions for CHECK_OP macro.
// The (int, int) specialization works around the issue that the compiler
// will not instantiate the template version of the function on values of
// unnamed enum type - see comment below.
...
TF_DEFINE_CHECK_OP_IMPL(Check_GE, >=)
TF_DEFINE_CHECK_OP_IMPL(Check_GT, >)
#undef TF_DEFINE_CHECK_OP_IMPL
