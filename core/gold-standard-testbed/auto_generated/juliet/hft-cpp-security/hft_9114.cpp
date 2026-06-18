// Vulnerable: HFT-9114
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_64b_badSink(&data);
