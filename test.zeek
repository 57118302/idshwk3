global dict : table[addr] of set[string] = table();
event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name=="USER-AGENT")
    {
        if(source_ip in test)
        {
            if(to_lower(value) !in test[source_ip])
            {
                add test[source_ip][to_lower(value)];
            }
        }
        else
        {
            test[source_ip]=set(to_lower(value));
        }
    }
}
event zeek_done()
{
	for (Addr, Set in test)
	{
		if(|Set|>=3)
		{
			print fmt("%s is a proxy",Addr);
		}
	}
}
