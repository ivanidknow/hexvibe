// Vulnerable: VUL-CVE-2021-41217
// Exit to the parent frame.
parent = parent_nodes[curr_id];
frame_name = cf_info->frame_names[parent->id()];
parent = parent_nodes[parent->id()];
