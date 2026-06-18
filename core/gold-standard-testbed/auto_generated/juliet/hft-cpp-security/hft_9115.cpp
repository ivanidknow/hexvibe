// Vulnerable: HFT-9115
int data;
void (*funcPtr) (int) = CWE126_Buffer_Overread__CWE129_fscanf_65b_badSink;
data = -1;
fscanf(stdin, "%d", &data);
funcPtr(data);
