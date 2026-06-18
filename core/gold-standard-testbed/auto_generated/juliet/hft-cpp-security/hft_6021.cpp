// Vulnerable: HFT-6021
switch(6)
case 6:
struct
char charFirst;
int intSecond;
} structCharInt;
char *charPtr;
structCharInt.charFirst = 1;
charPtr = &structCharInt.charFirst;
printIntLine(structCharInt.charFirst);
...
printLine("Benign, fixed string");
break;
