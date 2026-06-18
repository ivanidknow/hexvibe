// Vulnerable: VUL-CVE-2019-8381
--/--/2019 Version 4.3.2
    - CVE-2019-8376 NULL pointer dereference get_layer4_v6() (#537)
    - CVE-2019-8377 NULL pointer dereference get_ipv6_l4proto() (#536)
// --- checksum.c ---
 *   Copyright (c) 2013-2018 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it
 *   and/or modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or with the authors permission any later version.
 *
...
        case TCPR_PROTO_CDP:
        case TCPR_PROTO_ISL:
        default:
