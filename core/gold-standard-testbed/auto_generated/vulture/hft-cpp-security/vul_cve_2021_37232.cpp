// Vulnerable: VUL-CVE-2021-37232
- name: build
      run: cmake --build . --config Release
// --- extracts.cpp ---
void APar_ExtractDetails(FILE *isofile, uint8_t optional_output) {
  char uint32_buffer[5];
  Trackage track = {0};
