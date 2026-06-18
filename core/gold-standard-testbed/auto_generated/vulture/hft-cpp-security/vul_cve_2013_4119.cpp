// Vulnerable: VUL-CVE-2013-4119
ZeroMemory(&credssp->pubKeyAuth, sizeof(SecBuffer));
		ZeroMemory(&credssp->authInfo, sizeof(SecBuffer));

		if (credssp->server)
// --- peer.c ---
				IFCALLRET(client->Logon, client->authenticated, client, &client->identity, TRUE);
				credssp_free(rdp->nego->transport->credssp);
			}
			else
// --- sspi.c ---
	void* pointer;
...
		credssp_free(transport->credssp);
		return FALSE;
	}
