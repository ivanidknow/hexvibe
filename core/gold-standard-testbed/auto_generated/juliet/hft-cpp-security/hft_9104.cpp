// Vulnerable: HFT-9104
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_53b_badSink(data);
