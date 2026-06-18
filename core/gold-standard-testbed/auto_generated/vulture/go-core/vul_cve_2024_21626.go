// Vulnerable: VUL-CVE-2024-21626
}

	if err := parent.start(); err != nil {
		return fmt.Errorf("unable to start container process: %w", err)
// --- file.go ---
	TestMode bool

	cgroupFd     int = -1
	prepOnce     sync.Once
	prepErr      error
	resolveFlags uint64
...
	expected := "pwd: getcwd: Operation not permitted"
	actual := strings.Trim(buffers.Stderr.String(), "\n")
	if actual != expected {
