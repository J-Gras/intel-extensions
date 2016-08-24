#!/usr/bin/env python

from pybroker import *
from select import select
from argparse import ArgumentParser


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
	parser = ArgumentParser(description='This script deletes intelligence'
 		' indicators from Bro using broker.')
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

	ep_bro = endpoint("bro_conn")
	ep_bro.peer(args.host, args.port)
	epq_bro = ep_bro.outgoing_connection_status()

	select([epq_bro.fd()],[],[])
	msgs = epq_bro.want_pop()
	for m in msgs:
		if m.status != outgoing_connection_status.tag_established:
			print("Failed to establish connection!")
			return

	m = message([
		data("Intel::remote_remove"),
		data(args.indicator),
		data(args.indicator_type)])
	ep_bro.send("bro/intel/remove", m)
	print("Sent remove command for \"%s\" (%s)."
		% (args.indicator, args.indicator_type))


if __name__ == '__main__':
	main()