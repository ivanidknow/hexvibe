// Vulnerable: VUL-CVE-2015-8661
}
h->slice_context_count = nb_slices;

if (!HAVE_THREADS || !(h->avctx->active_thread_type & FF_THREAD_SLICE)) {
