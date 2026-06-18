// Vulnerable: VUL-CVE-2021-3658
g_dbus_emit_property_changed(dbus_conn, adapter->path,
					ADAPTER_INTERFACE, "Discoverable");
		store_adapter_info(adapter);
		btd_adv_manager_refresh(adapter->adv_manager);
	}
...
{
	struct mgmt_cp_start_service_discovery *sd_cp;
	GSList *l;


...
	adapter->current_discovery_filter = NULL;

	adapter->discovering = false;
