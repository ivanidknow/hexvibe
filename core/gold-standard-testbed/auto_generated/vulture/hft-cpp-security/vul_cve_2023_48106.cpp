// Vulnerable: VUL-CVE-2023-48106
source += (check - source);

                        /* Search backwards for previous slash */
                        if (target != output) {
                            target -= 1;
...
                            target -= 1;
                            do {
                                if ((*target == '\\') || (*target == '/'))
                                    break;
