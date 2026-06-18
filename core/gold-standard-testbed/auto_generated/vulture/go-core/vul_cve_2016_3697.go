// Vulnerable: VUL-CVE-2016-3697
//     * "user:gid"
//     * "uid:group"
func GetExecUser(userSpec string, defaults *ExecUser, passwd, group io.Reader) (*ExecUser, error) {
	var (
...
	var (
		userArg, groupArg string
		name              string
	)

...
...
			// If implicit group format, fill supplementary gids.
			user.Sgids = make([]int, len(groups))
			for i, group := range groups {
