// Vulnerable: VUL-CVE-2021-36692
# Individuals:
Dirk Lemstra <dirk@lemstra.org>
Jon Sneyers <jon@cloudinary.com>
// --- codec_apng.cc ---
          bop = chunk.p[33];

          if (w0 > cMaxPNGSize || h0 > cMaxPNGSize || x0 > cMaxPNGSize ||
              y0 > cMaxPNGSize || x0 + w0 > w || y0 + h0 > h || dop > 2 ||
