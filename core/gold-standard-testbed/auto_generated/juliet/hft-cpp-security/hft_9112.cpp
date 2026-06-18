// Vulnerable: HFT-9112
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_63b_badSink(&data);
