// Vulnerable: HFT-9101
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_51b_badSink(data);
