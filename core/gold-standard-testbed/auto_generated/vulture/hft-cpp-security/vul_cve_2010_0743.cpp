// Vulnerable: VUL-CVE-2010-0743
if (name)
		snprintf(mgmt->name, sizeof(mgmt->name), name);
	else {
		mgmt->name[0] = '\0';
...
				if (!ini)
					goto free_qry_mgmt;
				snprintf(ini->name, sizeof(ini->name), name);
				list_add(&ini->ilist, &target->isns_list);
			} else
