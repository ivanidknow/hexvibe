# Vulnerable: VUL-CVE-2021-44225
<busconfig>
	<policy user="root">
		<allow own="org.keepalived.Vrrp1"/>
		<allow send_destination="org.keepalived.Vrrp1"/>
	</policy>
	<policy context="default">
...
	</policy>
	<policy context="default">
		<allow send_interface="org.freedesktop.DBus.Introspectable" />
		<allow send_interface="org.freedesktop.DBus.Peer" />
		<allow send_interface="org.freedesktop.DBus.Properties" />
	</policy>
</busconfig>
