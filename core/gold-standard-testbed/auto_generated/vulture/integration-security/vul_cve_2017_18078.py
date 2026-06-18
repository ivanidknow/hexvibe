# Vulnerable: VUL-CVE-2017-18078
setup_suse() {
    ln -s ../usr/bin/systemctl $initdir/bin/systemctl
    ln -s ../usr/lib/systemd $initdir/lib/systemd
    inst_simple "/usr/lib/systemd/system/haveged.service"
}
