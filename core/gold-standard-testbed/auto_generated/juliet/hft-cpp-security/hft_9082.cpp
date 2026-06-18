// Vulnerable: HFT-9082
void bad()
int data;
data = -1;
CWE126_Buffer_Overread__CWE129_connect_socket_83_bad badObject(data);
