// Vulnerable: HFT-9163
void CWE126_Buffer_Overread__CWE129_listen_socket_66b_badSink(int dataArray[])
int data = dataArray[2];
int buffer[10] = { 0 };
if (data >= 0)
printIntLine(buffer[data]);
else
printLine("ERROR: Array index is negative");
