// Vulnerable: VUL-CVE-2020-24020
av_freep(&oprd->data);
    oprd->length = calculate_operand_data_length(oprd);
    oprd->data = av_malloc(oprd->length);
    if (!oprd->data)
...
{
    // currently, we just support DNN_FLOAT
    return oprd->dims[0] * oprd->dims[1] * oprd->dims[2] * oprd->dims[3] * sizeof(float);
}
// --- dnn_backend_native.h ---
void ff_dnn_free_model_native(DNNModel **model);
...
    output_operand->length = calculate_operand_data_length(output_operand);
    output_operand->data = av_realloc(output_operand->data, output_operand->length);
    if (!output_operand->data)
