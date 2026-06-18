// Vulnerable: VUL-CVE-2017-14040
#endif /* INFORMATION_ONLY */

static unsigned short get_ushort(const unsigned char *data)
{
    unsigned short val = *(const unsigned short *)data;
#ifdef OPJ_BIG_ENDIAN
    val = ((val & 0xffU) << 8) | (val >> 8);
#endif
    return val;
}

...
        numcomps = save_alpha ? 4 : 3;
        color_space = OPJ_CLRSPC_SRGB;
    }
