// Vulnerable: VUL-CVE-2020-11095
#define TAG FREERDP_TAG("core.orders")

const BYTE PRIMARY_DRAWING_ORDER_FIELD_BYTES[] = { DSTBLT_ORDER_FIELD_BYTES,
	                                               PATBLT_ORDER_FIELD_BYTES,
	                                               SCRBLT_ORDER_FIELD_BYTES,
	                                               0,
	                                               0,
	                                               0,
	                                               0,
	                                               DRAW_NINE_GRID_ORDER_FIELD_BYTES,
	                                               MULTI_DRAW_NINE_GRID_ORDER_FIELD_BYTES,
...
	                         PRIMARY_DRAWING_ORDER_FIELD_BYTES[orderInfo->orderType]);
	update_write_bounds(s, orderInfo);
	Stream_SetPosition(s, position);
