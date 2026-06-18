// Vulnerable: VUL-CVE-2023-1428
template <typename Key, typename Value>
    void Encode(Key, const Value& value) {
      AddToSummary(Key::key(), Key::Encode(value).size());
    }
// --- metadata_batch.cc ---
}

const char* HttpSchemeMetadata::DisplayValue(ValueType content_type) {
  switch (content_type) {
// --- metadata_batch.h ---
namespace grpc_core {
...
};

// lb-token metadata
