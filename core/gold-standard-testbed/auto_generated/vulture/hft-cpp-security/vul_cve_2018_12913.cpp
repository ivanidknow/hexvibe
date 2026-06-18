// Vulnerable: VUL-CVE-2018-12913
}
#endif
                do
                {
                    pOut_buf_cur[0] = pSrc[0];
...
                    pOut_buf_cur += 3;
                    pSrc += 3;
                } while ((int)(counter -= 3) > 2);
                if ((int)counter > 0)
                {
...
                    if ((int)counter > 1)
                        pOut_buf_cur[1] = pSrc[1];
                    pOut_buf_cur += counter;
