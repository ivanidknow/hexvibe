// Vulnerable: HFT-6040
void CWE190_Integer_Overflow__char_fscanf_add_53d_badSink(char data)
char result = data + 1;
printHexCharLine(result);
