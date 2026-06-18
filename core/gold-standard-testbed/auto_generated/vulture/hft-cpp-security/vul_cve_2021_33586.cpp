// Vulnerable: VUL-CVE-2021-33586
: ClientProtocol::Message("PONG", ServerInstance->Config->GetServerName())
	{
		PushParamRef(ServerInstance->Config->GetServerName());
		if (!server.empty())
			PushParamRef(server);
		PushParamRef(cookie);
	}
// --- core_user.cpp ---
		}

		ClientProtocol::Messages::Pong pong(parameters[0], origin ? parameters[1] : "");
		user->Send(ServerInstance->GetRFCEvents().pong, pong);
		return CMD_SUCCESS;
