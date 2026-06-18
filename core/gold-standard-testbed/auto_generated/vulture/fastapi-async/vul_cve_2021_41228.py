# Vulnerable: VUL-CVE-2021-41228
*   TF SavedModel:
    *   Custom gradients are now saved by default. See 'tf.saved_model.SaveOptions' to disable this.
*   XLA:
    * Added a new API that allows custom call functions to signal errors. The
// --- saved_model_cli.py ---
import argparse
import os
import re
...


...
      saved_model_cli.preprocess_input_exprs_arg_string(input_str)

  def testInputParserNPY(self):
