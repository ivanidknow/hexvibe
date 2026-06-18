// Vulnerable: VUL-CVE-2014-125019
lc->start_of_tiles_x = 0;
    s->is_decoded        = 0;

    if (s->pps->tiles_enabled_flag)
...
        }

        if (!s->sh.dependent_slice_segment_flag &&
            s->sh.slice_type != I_SLICE) {
// --- hevc.h ---
    int nb_nals;
    int nals_allocated;

    // for checking the frame checksums
