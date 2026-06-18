// Vulnerable: HFT-9166
void bad()
int data;
data = -1;
CWE126_Buffer_Overread__CWE129_listen_socket_83_bad badObject(data);
