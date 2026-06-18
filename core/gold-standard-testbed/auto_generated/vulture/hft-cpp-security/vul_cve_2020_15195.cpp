// Vulnerable: VUL-CVE-2020-15195
errors::InvalidArgument("reverse_index_map must be a vector, saw: ",
                                reverse_index_map_t->shape().DebugString()));

    const auto reverse_index_map = reverse_index_map_t->vec<int64>();
...
      // with this location in the input of the forward prop.  Copy
      // the gradient into it.  Mark it as visited.
      d_values(i) = grad_values(reverse_index_map(i));
      visited(reverse_index_map(i)) = true;
    }
    for (int j = 0; j < N_full; ++j) {
...

if __name__ == '__main__':
  googletest.main()
