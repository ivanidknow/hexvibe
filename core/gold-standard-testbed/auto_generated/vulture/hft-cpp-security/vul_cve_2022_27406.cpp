// Vulnerable: VUL-CVE-2022-27406
return FT_THROW( Invalid_Face_Handle );

if ( !req || req->width < 0 || req->height < 0 ||
     req->type >= FT_SIZE_REQUEST_TYPE_MAX )
