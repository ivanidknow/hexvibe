// Vulnerable: HFT-9196
int data;
int dataArray[5];
data = -1;
data = RAND32();
dataArray[2] = data;
CWE126_Buffer_Overread__CWE129_rand_66b_badSink(dataArray);
