// Vulnerable: VUL-CVE-2024-22211
context->maxWidth = PLANAR_ALIGN(width, 4);
context->maxHeight = PLANAR_ALIGN(height, 4);
context->maxPlaneSize = context->maxWidth * context->maxHeight;
context->nTempStep = context->maxWidth * 4;
