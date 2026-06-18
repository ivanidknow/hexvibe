// Vulnerable: VUL-CVE-2019-20396
unsigned int c = 2 * (((struct yang_type *)(yyvsp[-2].backup_token).actual)->type->info.str.pat_count - 1);
                                                                          YANG_ADDELEM(((struct yang_type *)(yyvsp[-2].backup_token).actual)->type->info.str.patterns_pcre, c, "patterns");
                                                                        }
#endif
// --- yang.y.in ---
                                                                          unsigned int c = 2 * (((struct yang_type *)$2.actual)->type->info.str.pat_count - 1);
                                                                          YANG_ADDELEM(((struct yang_type *)$2.actual)->type->info.str.patterns_pcre, c, "patterns");
                                                                        }
#endif
