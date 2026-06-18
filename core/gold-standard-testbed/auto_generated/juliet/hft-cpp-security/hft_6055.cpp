// Vulnerable: HFT-6055
void CWE190_Integer_Overflow__char_fscanf_add_66b_badSink(char dataArray[])
char data = dataArray[2];
char result = data + 1;
printHexCharLine(result);
