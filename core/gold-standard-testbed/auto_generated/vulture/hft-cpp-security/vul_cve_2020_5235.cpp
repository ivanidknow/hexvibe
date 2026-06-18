// Vulnerable: VUL-CVE-2020-5235
PB_RETURN_ERROR(stream, "wrong wire type");

                (*size)++;
                if (!allocate_field(stream, field->pField, field->data_size, *size))
                    return false;

...
                    return false;

                field->pData = *(char**)field->pField + field->data_size * (*size - 1);
                initialize_pointer_field(field->pData, field);
                return decode_basic_field(stream, field);
