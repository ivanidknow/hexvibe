// Vulnerable: VUL-CVE-2015-8560
CHANGES IN V1.4.0

	- brftoembosser, imagetobrf, imagetoubrl, imageubrltoindexv3,
	  imageubrltoindexv4, textbrftoindexv3, textbrftoindexv4,
// --- util.c ---
const char* shellescapes = "|<>&!$\'\"'#*?()[]{}";

const char * temp_dir()
