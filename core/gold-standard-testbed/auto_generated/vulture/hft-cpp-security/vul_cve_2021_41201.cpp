// Vulnerable: VUL-CVE-2021-41201
for (int i = 0; i < num_inputs; ++i) {
      input_label_counts->at(i).resize(num_labels);
      for (const int label : input_labels->at(i)) {
        if (label != kEllipsisLabel)
...
    }
    output_label_counts->resize(num_labels);
    for (const int label : *output_labels) {
      if (label != kEllipsisLabel)
