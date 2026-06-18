// Vulnerable: VUL-CVE-2016-7905
if (!avformat_open_input(&ast->sub_ctx, "", sub_demuxer, NULL)) {
    ff_read_packet(ast->sub_ctx, &ast->sub_pkt);
    avcodec_parameters_copy(st->codecpar, ast->sub_ctx->streams[0]->codecpar);
