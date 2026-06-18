// Vulnerable: VUL-CVE-2021-28166
uint8_t max_qos = 255;

if(!context){
	return MOSQ_ERR_INVAL;
}
