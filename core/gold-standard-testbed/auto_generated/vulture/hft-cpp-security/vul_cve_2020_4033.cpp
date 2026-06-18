// Vulnerable: VUL-CVE-2020-4033
if (code == LITE_SET_FG_FG_RUN || code == MEGA_MEGA_SET_FG_RUN)
				{
					SRCREADPIXEL(fgPel, pbSrc);
					SRCNEXTPIXEL(pbSrc);
...
				runLength = ExtractRunLength(code, pbSrc, &advance);
				pbSrc = pbSrc + advance;
				SRCREADPIXEL(pixelA, pbSrc);
				SRCNEXTPIXEL(pbSrc);
...
				SRCREADPIXEL(pixelA, pbSrc);
...
				UNROLL(runLength, {
					SRCREADPIXEL(temp, pbSrc);
					SRCNEXTPIXEL(pbSrc);
