# @TEST-EXEC: mkdir preserved_files
# @TEST-EXEC: zeek -r $TRACES/get.trace preserve_files %INPUT
# @TEST-EXEC: btest-diff intel.log
# @TEST-EXEC-FAIL: test -e preserved_files/extract-1362692527.009512-HTTP-FMnxxt3xjVcWNS2141

# Hit on FILE_HASH using a filter without FILE_HASH
@load frameworks/files/extract-all-files
@load frameworks/files/hash-all-files
@load frameworks/intel/seen/file-hashes

redef Intel::preserve_filter = {Intel::DOMAIN};

event zeek_init()
	{
	Intel::insert([$indicator="397168fd09991a0e712254df7bc639ac",
		$indicator_type=Intel::FILE_HASH, $meta=[$source="source1"]]);
	}

# @TEST-START-NEXT

# Multiple hits on the same file using a filter
@load frameworks/files/extract-all-files
@load frameworks/files/hash-all-files
@load frameworks/intel/seen/file-hashes
@load frameworks/intel/seen/file-names
@load frameworks/intel/seen/conn-established

redef Intel::preserve_filter = {Intel::DOMAIN};

event zeek_init()
	{
	Intel::insert([$indicator="397168fd09991a0e712254df7bc639ac",
		$indicator_type=Intel::FILE_HASH, $meta=[$source="source1"]]);
	Intel::insert([$indicator="test-filename",
		$indicator_type=Intel::FILE_NAME, $meta=[$source="source1"]]);
	Intel::insert([$indicator="141.142.228.5",
		$indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	}

event file_new(f: fa_file) &priority=10
	{
	f$info$filename = "test-filename";
	}
