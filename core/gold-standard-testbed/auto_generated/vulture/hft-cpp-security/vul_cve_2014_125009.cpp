// Vulnerable: VUL-CVE-2014-125009
dst -= src_x;
        src_x=0;
    }else if(src_x + b_w > w){
        b_w = w - src_x;
    }
...
            dst -= src_y*dst_stride;
        src_y=0;
    }else if(src_y + b_h> h){
        b_h = h - src_y;
    }
