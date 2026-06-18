// Vulnerable: VUL-CVE-2020-26268
void set_delete_on_deallocate() { delete_on_deallocate_ = true; }

private:
 std::unique_ptr<ReadOnlyMemoryRegion> memory_region_;
