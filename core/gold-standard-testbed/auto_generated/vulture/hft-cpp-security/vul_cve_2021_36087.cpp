// Vulnerable: VUL-CVE-2021-36087
struct cil_tree_node *in;
	struct cil_tree_node *macro;
	struct cil_tree_node *boolif;
};
...
	struct cil_tree_node *in = args->in;
	struct cil_tree_node *macro = args->macro;
	struct cil_tree_node *boolif = args->boolif;
	struct cil_tree_node *ast_node = NULL;
...
			rc = SEPOL_ERR;
...
			/* tuanbles and macros are not allowed in optionals*/
			cil_tree_log(node, CIL_ERR, "%s statement is not allowed in optionals", cil_node_to_string(node));
			rc = SEPOL_ERR;
