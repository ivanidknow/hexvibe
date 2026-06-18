# Vulnerable: VUL-CVE-2022-21733
@test_util.run_all_in_graph_and_eager_modes
@test_util.disable_tfrt
class RawOpsTest(test.TestCase, parameterized.TestCase):

...
  def testStringNGramsBadDataSplits(self, splits):
    data = ["aa", "bb", "cc", "dd", "ee", "ff"]
    with self.assertRaisesRegex(errors.InvalidArgumentError,
                                "Invalid split value"):
      self.evaluate(
          gen_string_ops.string_n_grams(
...
        // generate at least one ngram.
        int ngram_width = data_length + 2 * pad_width_;
        auto output_start = &ngrams_data[output_start_idx];
