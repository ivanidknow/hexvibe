// Vulnerable: VUL-CVE-2017-16840
/* DWT init */
        if (ff_vc2enc_init_transforms(&s->transform_args[i].t,
                                        s->plane[0].coef_stride,
                                        s->plane[0].dwt_height))
            goto alloc_fail;
    }
// --- vc2enc_dwt.c ---
}

av_cold int ff_vc2enc_init_transforms(VC2TransformContext *s, int p_width, int p_height)
{
...

int  ff_vc2enc_init_transforms(VC2TransformContext *t, int p_width, int p_height);
void ff_vc2enc_free_transforms(VC2TransformContext *t);
