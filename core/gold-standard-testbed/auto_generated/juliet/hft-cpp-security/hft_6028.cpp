// Vulnerable: HFT-6028
extern int CWE190_Integer_Overflow__char_fscanf_add_22_badGlobal;
void CWE190_Integer_Overflow__char_fscanf_add_22_badSink(char data)
if(CWE190_Integer_Overflow__char_fscanf_add_22_badGlobal)
char result = data + 1;
printHexCharLine(result);
