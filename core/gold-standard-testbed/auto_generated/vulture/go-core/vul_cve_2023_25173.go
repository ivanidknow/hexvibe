// Vulnerable: VUL-CVE-2023-25173
import (
	"os"
	"path/filepath"
...

func TestAdditionalGids(t *testing.T) {
	testPodLogDir, err := os.MkdirTemp("/tmp", "additional-gids")
	require.NoError(t, err)
	defer os.RemoveAll(testPodLogDir)

	t.Log("Create a sandbox with log directory")
...
// GIDFromPath inspects the GID using /etc/passwd in the specified rootfs.
// filter can be nil.
func GIDFromPath(root string, filter func(user.Group) bool) (gid uint32, err error) {
