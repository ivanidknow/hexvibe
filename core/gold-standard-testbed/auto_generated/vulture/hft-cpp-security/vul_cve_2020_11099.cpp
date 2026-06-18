// Vulnerable: VUL-CVE-2020-11099
goto out_free_blob;

	Stream_Read_UINT16(licenseStream, os_minor);
	Stream_Read_UINT16(licenseStream, os_major);
...

	/* CompanyName */
	Stream_Read_UINT32(licenseStream, cbCompanyName);
	if (Stream_GetRemainingLength(licenseStream) < cbCompanyName)
...

...
	/* licenseInfo */
	Stream_Read_UINT32(licenseStream, cbLicenseInfo);
	if (Stream_GetRemainingLength(licenseStream) < cbLicenseInfo)
