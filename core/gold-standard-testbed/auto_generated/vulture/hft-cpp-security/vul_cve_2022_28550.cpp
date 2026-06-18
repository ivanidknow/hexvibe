// Vulnerable: VUL-CVE-2022-28550
for (a=0;;a++){
    if (ApplyCommand[a] == '&'){
        if (ApplyCommand[a+1] == 'i'){
            // Input file.
