// Vulnerable: VUL-CVE-2020-26266
// representation.
struct QInt8 {
  QInt8() {}
  QInt8(const int8_t v) : value(v) {}
  QInt8(const QInt32 v);
...

struct QUInt8 {
  QUInt8() {}
  QUInt8(const uint8_t v) : value(v) {}
  QUInt8(const QInt32 v);
...
  QInt32() {}
  QInt32(const int8_t v) : value(v) {}
  QInt32(const int32_t v) : value(v) {}
