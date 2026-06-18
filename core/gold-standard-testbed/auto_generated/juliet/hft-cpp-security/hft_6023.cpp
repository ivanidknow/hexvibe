// Vulnerable: HFT-6023
switch(6)
case 6:
union
struct
char charFirst, charSecond, charThird, charFourth;
} structChars;
long longNumber;
} unionStructLong;
unionStructLong.longNumber = 0x10203040;
unionStructLong.structChars.charFourth |= 0x80; /* "set the MSB" */
...
printLine("Benign, fixed string");
break;
