# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run zeek-proc zeek remote_control %INPUT
# @TEST-EXEC: $UTILS/intel-mgr.py insert 1.0.0.1 ADDR > output
# @TEST-EXEC: $UTILS/intel-mgr.py query 1.0.0.1 ADDR >> output
# @TEST-EXEC: $UTILS/intel-mgr.py remove 1.0.0.1 ADDR >> output
# @TEST-EXEC: $UTILS/intel-mgr.py query 1.0.0.1 ADDR >> output
# @TEST-EXEC: $UTILS/intel-mgr.py remove 5.14.4.5 ADDR >> output
# @TEST-EXEC: cat zeek-proc/reporter.log >> output
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: btest-diff output

redef exit_only_after_terminate = T;

event Intel::remote_remove(indicator: string, indicator_type: string)
	{
	if ( indicator == "5.14.4.5" )
		terminate();
	}
