# Vulnerable: VUL-CVE-2021-37678
Functional models as well as Sequential models built with an explicit
    input shape are not affected.

* 'tf.lite':
// --- functional.py ---
  - Model cloning ('keras.models.clone')
  - Serialization ('model.get_config()/from_config', 'model.to_json()/to_yaml()'
  - Whole-model saving ('model.save()')
// --- functional_test.py ---
from tensorflow.python.platform import test
from tensorflow.python.training.tracking.util import Checkpoint
...
    config = yaml.load(yaml_string)
  from tensorflow.python.keras.layers import deserialize  # pylint: disable=g-import-not-at-top
  return deserialize(config, custom_objects=custom_objects)
