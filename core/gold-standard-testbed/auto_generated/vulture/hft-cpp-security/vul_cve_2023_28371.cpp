// Vulnerable: VUL-CVE-2023-28371
{
	QFile asFile;
	QFileInfo outputInfo(outputFile);
	QDir dir=outputInfo.dir(); // will hold complete dirname
	QFileInfo newFileNameInfo(name);

	bool okToSaveToAbsolutePath=StelApp::getInstance().getSettings()->value("scripts/flag_script_allow_write_absolute_path", false).toBool();
...
	QFileInfo newFileNameInfo(name);

	bool okToSaveToAbsolutePath=StelApp::getInstance().getSettings()->value("scripts/flag_script_allow_write_absolute_path", false).toBool();
...
	//! @note For storing to absolute path names, set [scripts]/flag_script_allow_write_absolute_path=true.
	//! Normally you would call saveOutputAs(...), then reset().
	static void saveOutputAs(const QString& name);
