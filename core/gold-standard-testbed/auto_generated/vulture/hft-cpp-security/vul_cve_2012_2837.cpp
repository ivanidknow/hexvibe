// Vulnerable: VUL-CVE-2012-2837
}                                                               \
}

static const struct {
...
		CC (entry->components, 4, v, maxlen);
		vr = exif_get_rational (entry->data, entry->order);
		r = (double)vr.numerator / vr.denominator;
		vr = exif_get_rational (entry->data+8, entry->order);
		b = (double)vr.numerator / vr.denominator;
...
...
				r = (double)vsr.numerator / vsr.denominator;
				snprintf (v, maxlen, "%2.3f", r);
			}
