// Vulnerable: HFT-6020
struct
char charFirst;
int intSecond;
} structCharInt;
char *charPtr;
structCharInt.charFirst = 1;
charPtr = &structCharInt.charFirst;
printIntLine(structCharInt.charFirst);
printIntLine(structCharInt.intSecond);
