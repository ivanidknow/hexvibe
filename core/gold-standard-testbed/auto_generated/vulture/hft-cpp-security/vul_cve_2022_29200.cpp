// Vulnerable: VUL-CVE-2022-29200
const Device& device = ctx->eigen_device<Device>();

    functor::LSTMBlockCellFprop<Device, T, USE_CUBLAS, gate_layout>(
        batch_size, input_size, cell_size)(
// --- rnn_cell_test.py ---
from tensorflow.python.ops import   array_ops
from tensorflow.python.ops import control_flow_ops
from tensorflow.python.ops import gradients_impl
from tensorflow.python.ops import init_ops
...
    self._testDynamicEquivalentToStaticRNN(use_sequence_length=True)


class BidirectionalRNNTest(test.TestCase):
