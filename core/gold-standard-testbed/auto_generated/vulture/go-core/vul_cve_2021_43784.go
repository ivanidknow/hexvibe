// Vulnerable: VUL-CVE-2021-43784
}

func (c *linuxContainer) newInitProcess(p *Process, cmd *exec.Cmd, messageSockPair, logFilePair filePair) (*initProcess, error) {
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initStandard))
...
	}
	_, sharePidns := nsMaps[configs.NEWPID]
	data, err := c.bootstrapData(c.config.Namespaces.CloneFlags(), nsMaps)
	if err != nil {
		return nil, err
...
...
	UidmapPathAttr   uint16 = 27288
	GidmapPathAttr   uint16 = 27289
)
