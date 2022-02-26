##! This script preserves extracted files in case of an intel hit.

@load base/frameworks/intel

module Intel;

export {
	## The prefix where files are preserved.
	const preserve_prefix = "./preserved_files/" &redef; 
}

event Intel::match(s: Seen, items: set[Item])
{
	if( s?$f && s$f?$info && s$f$info?$extracted)
	{
		local ex_file = s$f$info$extracted;
		local ex_path = cat(FileExtract::prefix, ex_file);
		local pre_path = cat(preserve_prefix, ex_file);

		# Move files using mv
		local ret = system(fmt("mv \"%s\" \"%s\"",
			safe_shell_quote(ex_path),
			safe_shell_quote(pre_path)
			));
	}
}