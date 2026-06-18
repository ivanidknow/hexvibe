// Vulnerable: HFT-9102
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_52b_badSink(data);
