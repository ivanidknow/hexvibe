// Vulnerable: VUL-CVE-2019-20917
void ModuleSQL::init()
{
	Dispatcher = new DispatcherThread(this);
	ServerInstance->Threads->Start(Dispatcher);
...
		delete Dispatcher;
	}
	for(ConnMap::iterator i = connections.begin(); i != connections.end(); i++)
	{
...
		delete i->second;
	}
}
