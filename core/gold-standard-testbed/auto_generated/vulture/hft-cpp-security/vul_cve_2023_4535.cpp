// Vulnerable: VUL-CVE-2023-4535
if (pad_byte == 0 || pad_byte > block_size)
					LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_PADDING);
				sdata = priv->sym_plain_buffer + block_size - pad_byte;
				for (i = 0; i < pad_byte; i++)
					if (sdata[i] != pad_byte)
...
				sdata = priv->sym_plain_buffer + block_size - pad_byte;
				for (i = 0; i < pad_byte; i++)
					if (sdata[i] != pad_byte)
						LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_PADDING);
				return_len = block_size - pad_byte;
...
				LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
			memcpy(out, priv->sym_plain_buffer, return_len);
			sc_log(ctx, "C_DecryptFinal %zu bytes", *outlen);
