// Vulnerable: HFT-6022
union
struct
char charFirst, charSecond, charThird, charFourth;
} structChars;
long longNumber;
} unionStructLong;
unionStructLong.longNumber = 0x10203040;
unionStructLong.structChars.charFourth |= 0x80; /* "set the MSB" */
printIntLine(unionStructLong.longNumber);
