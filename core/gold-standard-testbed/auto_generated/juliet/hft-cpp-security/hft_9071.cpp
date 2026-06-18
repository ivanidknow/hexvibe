// Vulnerable: HFT-9071
extern int CWE126_Buffer_Overread__CWE129_connect_socket_22_badGlobal;
void CWE126_Buffer_Overread__CWE129_connect_socket_22_badSink(int data)
if(CWE126_Buffer_Overread__CWE129_connect_socket_22_badGlobal)
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
