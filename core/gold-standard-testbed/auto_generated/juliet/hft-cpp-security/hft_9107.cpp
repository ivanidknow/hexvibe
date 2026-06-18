// Vulnerable: HFT-9107
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_54b_badSink(data);
