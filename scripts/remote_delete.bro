##! This script allows to remove intelligence items using broker.

module Intel;

export {
	## Broker port.
	const broker_port = 5012/tcp &redef;
	## Broker bind address.
	const broker_addr = 127.0.0.1 &redef;

	## Event to raise for intel item removal.
	global remote_remove: event(indicator: string, indicator_type: string);	
}

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

event bro_init()
	{
	Broker::enable();
	Broker::subscribe_to_events("bro/intel/remove");
	Broker::listen(broker_port, fmt("%s", broker_addr));
	}

event Intel::remote_remove(indicator: string, indicator_type: string)
	{
	local item: Item = [
		$indicator = indicator,
		$indicator_type = type_tbl[indicator_type],
		$meta = record($source = "")
	];
	remove(item, T);
	}