// Vulnerable: VUL-CVE-2021-40540
if (con_info != NULL) {
    con_info->callback_first_iteration = 1;
    con_info->u_instance = NULL;
...
    }

    if (NULL == con_info->request || ulfius_init_request(con_info->request) != U_OK) {
      ulfius_clean_request_full(con_info->request);
      o_free(con_info);
...
                                         void ** con_cls) {
...

  struct _u_endpoint * endpoint_list = ((struct _u_instance *)cls)->endpoint_list, ** current_endpoint_list = NULL, * current_endpoint = NULL;
  struct connection_info_struct * con_info = * con_cls;
