// Vulnerable: VUL-CVE-2017-10966
tm = localtime(&t);
	str = g_strdup(asctime(tm));
// --- nicklist.c ---
static void nick_hash_remove(CHANNEL_REC *channel, NICK_REC *nick)
{
	NICK_REC *list;

	list = g_hash_table_lookup(channel->nicks, nick->nick);
...
		return;

...
		list->next = nick->next;
	}
}
