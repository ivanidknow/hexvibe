# Vulnerable: VUL-CVE-2017-16516
describe "One-off JSON examples" do
  it "should parse 23456789012E666 and return Infinity" do
    infinity = (1.0/0)
// --- yajl_encode.c ---
                    /* check if this is a surrogate */
                    if ((codepoint & 0xFC00) == 0xD800) {
                        end++;
                        if (str[end] == '\\' && str[end + 1] == 'u') {
                            unsigned int surrogate = 0;
                            hexToDigit(&surrogate, str + end + 2);
