// Vulnerable: VUL-CVE-2017-9831
current_params->device_flags = rawdevice->device_entry.device_flags;
  current_params->nrofobjects = 0;
  current_params->objects = NULL;
  current_params->response_packet_size = 0;
// --- ptp-pack.c ---
 *
 * Copyright (C) 2001-2004 Mariusz Woloszyn <emsi@ipartners.pl>
 * Copyright (C) 2003-2014 Marcus Meissner <marcus@jet.franken.de>
 * Copyright (C) 2006-2008 Linus Walleij <triad@df.lth.se>
 * Copyright (C) 2007 Tero Saarni <tero.saarni@gmail.com>
...
...
#define ptp_canon_setobjectarchive(params,oid,flags) ptp_generic_no_data(params,PTP_OC_CANON_SetObjectArchive,2,oid,flags)
uint16_t ptp_canon_get_customize_data (PTPParams* params, uint32_t themenr,
				unsigned char **data, unsigned int *size);
