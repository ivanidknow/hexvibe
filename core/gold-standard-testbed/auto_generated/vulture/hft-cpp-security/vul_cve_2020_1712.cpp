// Vulnerable: VUL-CVE-2020-1712
LIBSYSTEMD_245 {
global:
        sd_bus_message_dump;
        sd_bus_message_sensitive;
// --- sd-bus.c ---
        return bus->close_on_exit;
}
// --- sd-bus.h ---
int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec);
int sd_bus_flush(sd_bus *bus);

sd_bus_slot* sd_bus_get_current_slot(sd_bus *bus);
