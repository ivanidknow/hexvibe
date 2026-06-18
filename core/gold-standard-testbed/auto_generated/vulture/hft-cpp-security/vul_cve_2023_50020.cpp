// Vulnerable: VUL-CVE-2023-50020
if (received & EPOLLRDHUP) {
        when |= OGS_POLLIN;
    }
}
