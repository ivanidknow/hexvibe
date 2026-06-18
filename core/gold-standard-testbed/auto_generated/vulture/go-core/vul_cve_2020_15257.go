// Vulnerable: VUL-CVE-2020-15257
config := b.shimConfig(ns, c, ropts)
		return config,
			client.WithStart(c.Shim, b.shimAddress(ns), daemonAddress, cgroup, c.ShimDebug, exitHandler)
	}
}
...
// Delete deletes the bundle from disk
func (b *bundle) Delete() error {
	err := atomicDelete(b.path)
	if err == nil {
...
...

	return empty, nil
}
