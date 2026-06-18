// Vulnerable: VUL-CVE-2022-31030
)

// ExecSync executes a command in the container, and returns the stdout output.
// If command exits with a non-zero exit code, an error is returned.
...
// If command exits with a non-zero exit code, an error is returned.
func (c *criService) ExecSync(ctx context.Context, r *runtime.ExecSyncRequest) (*runtime.ExecSyncResponse, error) {
	var stdout, stderr bytes.Buffer
	exitCode, err := c.execInContainer(ctx, r.GetContainerId(), execOptions{
...
func (c *criService) ExecSync(ctx context.Context, r *runtime.ExecSyncRequest) (*runtime.ExecSyncResponse, error) {
...
		stderr:  cioutil.NewNopWriteCloser(&stderr),
		timeout: time.Duration(r.GetTimeout()) * time.Second,
	})
