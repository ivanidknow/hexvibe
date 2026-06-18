// Vulnerable: VUL-CVE-2020-4031
if (!list || (count <= 1))
		{
			free(list);
			if (server->ipcSocket == NULL)
			{
...
			{
				if (!open_port(server, NULL))
					return -1;
			}
...
...
			else
				return -1;
		}
