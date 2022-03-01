# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: mkdir preserved_files
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -r $TRACES/get.trace %INPUT
# @TEST-EXEC: btest-bg-wait -k 13
# @TEST-EXEC: btest-diff manager-1/intel.log
# @TEST-EXEC: test -e preserved_files/extract-1362692527.009512-HTTP-FMnxxt3xjVcWNS2141

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1"],
};
# @TEST-END-FILE

# Scenario: Hit on FILE_HASH
@load preserve_files
@load frameworks/files/extract-all-files
@load frameworks/files/hash-all-files
@load frameworks/intel/seen/file-hashes

redef Log::default_rotation_interval = 0secs;
redef Intel::preserve_prefix = "../preserved_files/";

module Intel;

# Manager

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event Cluster::node_up(name: string, id: string)
	{
	# Insert the data once all workers are connected.
	if ( Cluster::worker_count == 1 )
		{
		Intel::insert([$indicator="397168fd09991a0e712254df7bc639ac",
			$indicator_type=Intel::FILE_HASH, $meta=[$source="source1"]]);
		}
	}
@endif

# Worker

@if ( Cluster::local_node_type() == Cluster::WORKER )
event zeek_init()
	{
	suspend_processing();
	}

event Intel::insert_indicator(item: Intel::Item)
	{
	# Run test on worker-1 when item has been inserted
	if ( Cluster::node == "worker-1" )
		continue_processing();
	}
@endif

# Shutdown logic

event die()
	{
	terminate();
	}

event Intel::log_intel(rec: Intel::Info)
	{
	if ( "source1" in rec$sources )
		schedule 2sec { die() };
	}

event Cluster::node_down(name: string, id: string)
	{
	# Cascading termination
	schedule 2sec { die() };
	}

# @TEST-START-NEXT

# Scenario: Multiple hits on the same file
@load preserve_files
@load frameworks/files/extract-all-files
@load frameworks/files/hash-all-files
@load frameworks/intel/seen/file-hashes
@load frameworks/intel/seen/file-names
@load frameworks/intel/seen/conn-established

redef Log::default_rotation_interval = 0secs;
redef Intel::preserve_prefix = "../preserved_files/";

module Intel;

# Manager

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event Cluster::node_up(name: string, id: string)
	{
	# Insert the data once all workers are connected.
	if ( Cluster::worker_count == 1 )
		{
		Intel::insert([$indicator="397168fd09991a0e712254df7bc639ac",
			$indicator_type=Intel::FILE_HASH, $meta=[$source="source1"]]);
		Intel::insert([$indicator="test-filename",
			$indicator_type=Intel::FILE_NAME, $meta=[$source="source1"]]);
		Intel::insert([$indicator="141.142.228.5",
			$indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
		}
	}
@endif

# Worker

@if ( Cluster::local_node_type() == Cluster::WORKER )
event zeek_init()
	{
	suspend_processing();
	}

global worker_data = 0;
event Intel::insert_indicator(item: Intel::Item)
	{
	# Run test on worker-1 when all items have been inserted
	if ( Cluster::node == "worker-1" )
		{
		++worker_data;
		if ( worker_data == 3 )
			continue_processing();
		}
	}

event file_new(f: fa_file) &priority=10
	{
	f$info$filename = "test-filename";
	}
@endif

# Shutdown logic

event die()
	{
	terminate();
	}

event Intel::log_intel(rec: Intel::Info)
	{
	if ( "source1" in rec$sources )
		schedule 2sec { die() };
	}

event Cluster::node_down(name: string, id: string)
	{
	# Cascading termination
	schedule 2sec { die() };
	}
