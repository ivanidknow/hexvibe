// Vulnerable: VUL-CVE-2006-4168
libexif-0.6.16:
  * Updated translations: cz, pl, vi
// --- configure.ac ---
AC_PREREQ(2.59)
AC_INIT([EXIF library], [0.6.15], [libexif-devel@lists.sourceforge.net], [libexif])
AC_CONFIG_SRCDIR([libexif/exif-data.h])
AC_CONFIG_HEADERS([config.h])
// --- exif-data.c ---
		  exif_tag_get_name (entry->tag));

	/*
...
		return 0;
	if (s > 4)
		doff = exif_get_long (d + offset + 8, data->priv->order);
