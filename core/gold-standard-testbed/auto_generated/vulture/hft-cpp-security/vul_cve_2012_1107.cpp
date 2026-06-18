// Vulnerable: VUL-CVE-2012-1107
uint finalFrameBlocks = header.mid(8, 4).toUInt(false);
  uint totalBlocks = totalFrames > 0 ? (totalFrames -  1) * blocksPerFrame + finalFrameBlocks : 0;
  d->length = totalBlocks / d->sampleRate;
  d->bitrate = d->length > 0 ? ((d->streamLength * 8L) / d->length) / 1000 : 0;
}
