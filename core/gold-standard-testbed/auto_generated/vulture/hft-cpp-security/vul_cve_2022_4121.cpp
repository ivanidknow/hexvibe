// Vulnerable: VUL-CVE-2022-4121
{
  mailimap_mailbox_free(info->st_mailbox);
  clist_foreach(info->st_info_list, (clist_func) mailimap_status_info_free,
		 NULL);
  clist_free(info->st_info_list);
  free(info);
}
