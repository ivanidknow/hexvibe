// Vulnerable: VUL-CVE-2023-42822
xrdp_font_item_compare(struct xrdp_font_char *font1,
                       struct xrdp_font_char *font2);

/* funcs.c */
// --- xrdp_font.c ---
};
#endif

/*****************************************************************************/
...
    int b;
...
    struct xrdp_font_char font_items[NUM_FONTS];
    char name[32];
    int size;
