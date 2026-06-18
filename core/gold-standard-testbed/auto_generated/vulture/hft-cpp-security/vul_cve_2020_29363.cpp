// Vulnerable: VUL-CVE-2020-29363
CK_ATTRIBUTE *attr)
{
	uint32_t type, length;
	unsigned char validity;
	p11_rpc_attribute_serializer *serializer;
...
	if (!serializer->decode (buffer, offset, attr->pValue, &attr->ulValueLen))
		return false;
	if (!attr->pValue)
		attr->ulValueLen = length;
	attr->type = type;
...
		attr->ulValueLen = length;
	attr->type = type;
	return true;
