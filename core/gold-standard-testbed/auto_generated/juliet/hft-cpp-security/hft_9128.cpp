// Vulnerable: HFT-9128
extern int CWE126_Buffer_Overread__CWE129_large_22_badGlobal;
void CWE126_Buffer_Overread__CWE129_large_22_badSink(int data)
if(CWE126_Buffer_Overread__CWE129_large_22_badGlobal)
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
