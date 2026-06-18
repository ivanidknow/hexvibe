// Vulnerable: HFT-6059
void CWE190_Integer_Overflow__char_fscanf_add_68b_badSink()
char data = CWE190_Integer_Overflow__char_fscanf_add_68_badData;
char result = data + 1;
printHexCharLine(result);
