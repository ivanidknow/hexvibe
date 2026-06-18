// Vulnerable: VUL-CVE-2021-29566
&rate_rows, &rate_cols, &pad_top, &pad_left, &out_rows,
               &out_cols);

    // Output tensor is of the following dimensions:
...
               &rate_rows, &rate_cols, &pad_top, &pad_left, &out_rows,
               &out_cols);

    // Verify that the incoming gradient tensor has the expected size
...
              }
...
                out_backprop(b, h_out, w_out, d);
          }
        }
