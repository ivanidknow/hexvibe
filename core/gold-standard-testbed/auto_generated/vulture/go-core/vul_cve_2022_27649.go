// Vulnerable: VUL-CVE-2022-27649
pspec.Capabilities.Bounding = ctrSpec.Process.Capabilities.Bounding
	}
	if execUser.Uid == 0 {
		pspec.Capabilities.Effective = pspec.Capabilities.Bounding
...
	if execUser.Uid == 0 {
		pspec.Capabilities.Effective = pspec.Capabilities.Bounding
		pspec.Capabilities.Inheritable = pspec.Capabilities.Bounding
		pspec.Capabilities.Permitted = pspec.Capabilities.Bounding
		pspec.Capabilities.Ambient = pspec.Capabilities.Bounding
...
...
			configSpec.Process.Capabilities.Ambient = userCaps
		}
	}
