// Vulnerable: HFT-9164
void CWE126_Buffer_Overread__CWE129_listen_socket_67b_badSink(CWE126_Buffer_Overread__CWE129_listen_socket_67_structType myStruct)
int data = myStruct.structFirst;
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
