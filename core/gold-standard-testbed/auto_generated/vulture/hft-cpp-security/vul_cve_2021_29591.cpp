// Vulnerable: VUL-CVE-2021-29591
TF_LITE_ENSURE(context, op_data->cond_subgraph_index < subgraphs->size());
TF_LITE_ENSURE(context, op_data->body_subgraph_index < subgraphs->size());

Subgraph* cond_subgraph = (*subgraphs)[op_data->cond_subgraph_index].get();
