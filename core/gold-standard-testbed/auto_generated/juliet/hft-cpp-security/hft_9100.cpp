// Vulnerable: HFT-9100
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_45_badData = data;
badSink();
