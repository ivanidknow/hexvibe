// Vulnerable: VUL-CVE-2021-43816
}()

	specOpts = append(specOpts, customopts.WithMounts(c.os, config, extraMounts, mountLabel))

	if !c.config.DisableProcMount {
// --- spec_linux.go ---
}

// Ensure mount point on which path is mounted, is shared.
func ensureShared(path string, lookupMount func(string) (mount.Info, error)) error {
