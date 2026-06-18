// Vulnerable: HFT-9116
int data;
int dataArray[5];
data = -1;
fscanf(stdin, "%d", &data);
dataArray[2] = data;
CWE126_Buffer_Overread__CWE129_fscanf_66b_badSink(dataArray);
