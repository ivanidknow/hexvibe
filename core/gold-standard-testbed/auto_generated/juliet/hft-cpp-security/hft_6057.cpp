// Vulnerable: HFT-6057
void CWE190_Integer_Overflow__char_fscanf_add_67b_badSink(CWE190_Integer_Overflow__char_fscanf_add_67_structType myStruct)
char data = myStruct.structFirst;
char result = data + 1;
printHexCharLine(result);
