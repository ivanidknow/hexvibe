# Vulnerable: VUL-CVE-2022-29202
raise ValueError("Invalid pylist=%r: empty list nesting is greater "
                     "than scalar value nesting" % pylist)

# If both inner_shape and ragged_rank were specified, then check that
