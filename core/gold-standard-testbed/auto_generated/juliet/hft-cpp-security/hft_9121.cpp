// Vulnerable: HFT-9121
void CWE126_Buffer_Overread__CWE129_fscanf_68b_badSink()
int data = CWE126_Buffer_Overread__CWE129_fscanf_68_badData;
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
