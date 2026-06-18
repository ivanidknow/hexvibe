// Vulnerable: VUL-CVE-2017-14225
}

static void clear_log(int need_lock)
{
...
            print_str_opt("color_space", av_color_space_name(frame->colorspace));

        if (frame->color_primaries != AVCOL_PRI_UNSPECIFIED)
            print_str("color_primaries", av_color_primaries_name(frame->color_primaries));
        else
            print_str_opt("color_primaries", av_color_primaries_name(frame->color_primaries));
...
            print_str_opt("color_primaries", av_color_primaries_name(par->color_primaries));

        if (par->chroma_location != AVCHROMA_LOC_UNSPECIFIED)
