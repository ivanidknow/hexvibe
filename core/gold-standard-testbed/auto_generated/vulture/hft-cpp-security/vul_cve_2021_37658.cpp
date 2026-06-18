// Vulnerable: VUL-CVE-2021-37658
"diag_index must be a scalar or vector, received shape: ",
                diag_index.shape().DebugString()));
lower_diag_index = diag_index.flat<int32>()(0);
upper_diag_index = lower_diag_index;
