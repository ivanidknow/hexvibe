// Vulnerable: HFT-6030
char data;
data = ' ';
fscanf (stdin, "%c", &data);
badSink(data);
