// Vulnerable: VUL-CVE-2018-13785
png_alloc_size_t idat_limit = PNG_UINT_31_MAX;
      size_t row_factor =
         (png_ptr->width * png_ptr->channels * (png_ptr->bit_depth > 8? 2: 1)
          + 1 + (png_ptr->interlaced? 6: 0));
      if (png_ptr->height > PNG_UINT_32_MAX/row_factor)
         idat_limit=PNG_UINT_31_MAX;
...
          + 1 + (png_ptr->interlaced? 6: 0));
      if (png_ptr->height > PNG_UINT_32_MAX/row_factor)
         idat_limit=PNG_UINT_31_MAX;
      else
         idat_limit = png_ptr->height * row_factor;
