// Vulnerable: HFT-9145
int data;
int dataArray[5];
data = -1;
data = 10;
dataArray[2] = data;
CWE126_Buffer_Overread__CWE129_large_66b_badSink(dataArray);
