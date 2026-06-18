// Vulnerable: VUL-CVE-2015-8216
if(dc == 0xFFFFF)
                            return -1;
                        if(bits<=8){
                        ptr = s->picture_ptr->data[c] + (linesize * (v * mb_y + y)) + (h * mb_x + x); //FIXME optimize this crap
                        if(y==0 && toprow){
...
                        if(dc == 0xFFFFF)
                            return -1;
                        if(bits<=8){
                            ptr = s->picture_ptr->data[c] +
                              (linesize * (v * mb_y + y)) +
