// Vulnerable: VUL-CVE-2020-8036
*/

struct tok message_type_values[] = {
    { 0x00, "REQUEST" },
    { 0x01, "REQUEST_NO_RETURN" },
...
};

struct tok return_code_values[] = {
    { 0x00, "E_OK" },
    { 0x01, "E_NOT_OK" },
...
    { 0x0e, "E_E2E_NOT_AVAILABLE" },
    { 0x0f, "E_E2E_NO_NEW_DATA" },
};
