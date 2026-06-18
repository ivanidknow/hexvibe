// Vulnerable: HFT-9124
void bad()
int data;
data = -1;
CWE126_Buffer_Overread__CWE129_fscanf_83_bad badObject(data);
