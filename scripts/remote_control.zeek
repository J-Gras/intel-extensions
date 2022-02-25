##! This script allows to remove intelligence items using broker.

module Intel;

export {
	## Broker port.
	option broker_port = 5012/tcp;
	## Broker bind address.
	option broker_addr = 127.0.0.1;

	## Event to raise for intel item query.
	global remote_query: event(indicator: string, indicator_type: string);
	## Event to raise for intel item removal.
	global remote_remove: event(indicator: string, indicator_type: string);
	## Event to raise for intel item insertion.
	global remote_insert: event(indicator: string, indicator_type: string);
}

global remote_query_reply: event(success: bool, indicator: string);
global remote_remove_reply: event(success: bool, indicator: string);
global remote_insert_reply: event(success: bool, indicator: string);

redef enum Where += {
	# Location used for lookups from remote
	Intel::REMOTE,
};

global type_tbl: table[string] of Type = {
		["ADDR"] = ADDR,
		["SUBNET"] = SUBNET,
		["URL"] = URL,
		["SOFTWARE"] = SOFTWARE,
		["EMAIL"] = EMAIL,
		["DOMAIN"] = DOMAIN,
		["USER_NAME"] = USER_NAME,
		["CERT_HASH"] = CERT_HASH,
		["PUBKEY_HASH"] = PUBKEY_HASH,
};

function compose_seen(indicator: string, indicator_type: Type): Seen
	{
	local res: Seen = [
		$indicator      = indicator,
		$indicator_type = indicator_type,
		$where          = Intel::REMOTE
	];
	
	if ( indicator_type == ADDR )
		{
		res$host = to_addr(indicator);
		}
	
	return res;
	}

function compose_item(indicator: string, indicator_type: Type): Item
	{
	local res: Item = [
		$indicator      = indicator,
		$indicator_type = indicator_type,
		$meta = record(
			$source	= "intel-remote"
		)
	];

	return res;
	}

event zeek_init()
	{
	Broker::subscribe("zeek/intel/");
	Broker::listen(fmt("%s", broker_addr), broker_port);
	}

event Intel::remote_query(indicator: string, indicator_type: string)
	{
	local s = compose_seen(indicator, type_tbl[indicator_type]);
	# Lookup indicator and return result
	Broker::publish("zeek/intel/query", remote_query_reply, find(s), indicator);
	}

event Intel::remote_remove(indicator: string, indicator_type: string)
	{
	local item = compose_item(indicator, type_tbl[indicator_type]);
	remove(item, T);
	# Always indicate success
	Broker::publish("zeek/intel/remove", remote_remove_reply, T, indicator);
	}

event Intel::remote_insert(indicator: string, indicator_type: string)
	{
	local item = compose_item(indicator, type_tbl[indicator_type]);
	insert(item);
	# Always indicate success
	Broker::publish("zeek/intel/insert", remote_insert_reply, T, indicator);
	}
