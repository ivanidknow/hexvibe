// Vulnerable: VUL-CVE-2023-25809
[ "$status" -eq 0 ]
}
// --- rootfs_linux.go ---
		return err
	}
	return utils.WithProcfd(c.root, m.Destination, func(procfd string) error {
		if err := mount(m.Source, m.Destination, procfd, "cgroup2", uintptr(m.Flags), m.Data); err != nil {
			// when we are in UserNS but CgroupNS is not unshared, we cannot mount cgroup2 (#2158)
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EBUSY) {
				src := fs2.UnifiedMountpoint
				if c.cgroupns && c.cgroup2Path != "" {
...
		return nil
	})
}
