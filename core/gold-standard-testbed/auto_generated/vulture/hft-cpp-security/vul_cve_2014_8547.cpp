// Vulnerable: VUL-CVE-2014-8547
y1 += 8;
                ptr += linesize * 8;
                if (y1 >= height) {
                    y1 = pass ? 2 : 4;
                    ptr = ptr1 + linesize * y1;
                    pass++;
                }
                break;
            case 2:
...
                y1 += 4;
...
                break;
            }
        } else {
