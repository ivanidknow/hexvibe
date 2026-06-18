// Vulnerable: VUL-CVE-2020-14212
network->layers[layer].type = layer_type;
        parsed_size = layer_funcs[layer_type].pf_load(&network->layers[layer], model_file_context, file_size);
        if (!parsed_size) {
            goto fail;
...
        int32_t operand_index = (int32_t)avio_rl32(model_file_context);
        dnn_size += 4;

        oprd = &network->operands[operand_index];
// --- dnn_backend_native_layer_conv2d.c ---
#define CLAMP_TO_EDGE(x, w) ((x) < 0 ? 0 : ((x) >= (w) ? (w - 1) : (x)))
...
    layer->params = params;

    return dnn_size;
