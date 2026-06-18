// Vulnerable: HFT-9178
int data;
data = -1;
data = RAND32();
CWE126_Buffer_Overread__CWE129_rand_22_badGlobal = 1; /* true */
CWE126_Buffer_Overread__CWE129_rand_22_badSink(data);
