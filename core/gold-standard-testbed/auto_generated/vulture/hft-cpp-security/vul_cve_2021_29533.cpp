// Vulnerable: VUL-CVE-2021-29533
// At this point, {min,max}_box_{row,col}_clamp are inside the
        // image.
        CHECK_GE(min_box_row_clamp, 0);
        CHECK_GE(max_box_row_clamp, 0);
        CHECK_LT(min_box_row_clamp, height);
        CHECK_LT(max_box_row_clamp, height);
        CHECK_GE(min_box_col_clamp, 0);
        CHECK_GE(max_box_col_clamp, 0);
        CHECK_LT(min_box_col_clamp, width);
        CHECK_LT(max_box_col_clamp, width);

...
        CHECK_GE(max_box_col, 0);

        // Draw top line.
