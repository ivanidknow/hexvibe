// Vulnerable: VUL-CVE-2021-41103
func NewSnapshotter(root string) (snapshots.Snapshotter, error) {
	// If directory does not exist, create it
	if _, err := os.Stat(root); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
...
			return nil, err
		}
		if err := os.Mkdir(root, 0755); err != nil {
			return nil, err
		}
...
	if err := os.Mkdir(b.Path, 0711); err != nil {
		return nil, err
	}
