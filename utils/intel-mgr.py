#!/usr/bin/env python3

import broker

from argparse import ArgumentParser

operations = (
	'query',
	'remove',
	'insert')

intel_types = (
	'ADDR',
	'SUBNET',
	'URL',
	'SOFTWARE',
	'EMAIL',
	'DOMAIN',
	'USER_NAME',
	'CERT_HASH',
	'PUBKEY_HASH')



def get_arguments():
	parser = ArgumentParser(description='This script allows to manage'
		' intelligence indicators of a Zeek instance using broker.')
	parser.add_argument('operation', metavar='OPERATION', type=str.lower,
		choices=operations, help='Operation to execute')
	parser.add_argument('indicator', metavar='INDICATOR', type=str,
		help='Intel indicator')
	parser.add_argument('indicator_type', metavar='TYPE', type=str.upper,
		choices=intel_types, help='Intel indicator\'s type')
	parser.add_argument('-p', metavar='PORT', type=int, default=5012,
		dest='port', help='Broker port (default: 5012)')
	parser.add_argument('-a', metavar='IP', type=str, default='127.0.0.1',
		dest='host', help='Broker host (default: 127.0.0.1)')
	return parser.parse_args()


def main():
	args = get_arguments()
	op = args.operation

	ep_zeek = broker.Endpoint()
	sub_zeek_intel = ep_zeek.make_subscriber(f"zeek/intel/{op}")
	sub_zeek_state = ep_zeek.make_status_subscriber(True)
	ep_zeek.peer(args.host, args.port, retry=0)

	# Establish connection
	#TODO: see https://github.com/zeek/broker/issues/18
	for st in sub_zeek_state.get(1, 0.5):
		if not (type(st) == broker.Status and st.code() == broker.SC.PeerAdded):
			print(f"Failed to establish connection! ({st.code()})")
			return

	# Send operation
	evt_op = broker.zeek.Event(f"Intel::remote_{op}",
		args.indicator,
		args.indicator_type)
	ep_zeek.publish(f"zeek/intel/{op}", evt_op)
	print(f"Sent {op} command for \"{args.indicator}\" ({args.indicator_type}).")

	# Await reply
	for (topic, data) in sub_zeek_intel.get(1, 2.0):
		evt_rep = broker.zeek.Event(data)
		if evt_rep.name() != f"Intel::remote_{op}_reply":
			print("Received unexpected event.")
			return
		success = evt_rep.args()[0]
		indicator = evt_rep.args()[1]
		if success:
			print(f"Successfully executed {op} \"{indicator}\"")
		else:
			print(f"Failed to {op} \"{indicator}\"")
		return

	print("Request timed out.");
	return

if __name__ == '__main__':
	main()
