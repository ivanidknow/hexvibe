// Vulnerable: HFT-9097
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_22_badGlobal = 1; /* true */
CWE126_Buffer_Overread__CWE129_fscanf_22_badSink(data);
