# @TEST-EXEC: mkdir preserved_files
# @TEST-EXEC: zeek -r $TRACES/get.trace preserve_files %INPUT
# @TEST-EXEC: test -e preserved_files/extract-1362692527.009512-HTTP-FMnxxt3xjVcWNS2141

@load frameworks/files/extract-all-files
@load frameworks/files/hash-all-files
@load frameworks/intel/seen/file-hashes

event zeek_init()
	{
	Intel::insert([$indicator="397168fd09991a0e712254df7bc639ac",
		$indicator_type=Intel::FILE_HASH, $meta=[$source="source1"]]);
	}
