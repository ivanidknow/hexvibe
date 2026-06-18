// Vulnerable: VUL-CVE-2021-41203
template <typename T>
struct SaveTypeTraits;

template <typename T>
...
  TENSOR_PROTO_EXTRACT_TYPE_HELPER(TYPE, FIELD, FTYPE, FTYPE)     \
  template <>                                                     \
  inline void Fill(const TYPE* data, size_t n, TensorProto* t) {  \
    typename protobuf::RepeatedField<FTYPE> copy(data, data + n); \
...
#define TENSOR_PROTO_EXTRACT_TYPE_COMPLEX(TYPE, FIELD, FTYPE)       \
...

void CachedTensorSliceReaderTesterHelper(
    const TensorSliceWriter::CreateBuilderFunction& create_function,
