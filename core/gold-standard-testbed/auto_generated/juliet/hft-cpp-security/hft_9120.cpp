// Vulnerable: HFT-9120
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_68_badData = data;
CWE126_Buffer_Overread__CWE129_fscanf_68b_badSink();
