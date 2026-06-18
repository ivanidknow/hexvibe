// Vulnerable: CSH-070
return  Double.Epsilon <= Math.Abs(v1 - v2);
}
static bool uselessZeroEqual(){
    double v1 = 0;
    double v2 = 0;
