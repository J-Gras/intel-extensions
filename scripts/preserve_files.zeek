##! This script preserves extracted files in case of an intel hit.

@load base/frameworks/intel
@load base/frameworks/files

module Intel;

export {
	## The prefix where files are preserved.
	option preserve_prefix = "./preserved_files/";

	## By default files will be preserved if they are in any way
	## associated to an intel hit. By adding intel types to this
	## filter, only files with corresponding hits will be moved.
	option preserve_filter: Intel::TypeSet = {};

	redef record connection += {
		## Indicate whether intel matched in this connection.
		intel_hit: bool &default = F;
	};

	## Preservation state of a file.
	type PreserveState: enum { SKIP_FILE, KEEP_FILE, FILE_MOVED };

	redef record Files::Info += {
		## Indicate whether the file should be moved after extraction.
		preserve_state: PreserveState &default = SKIP_FILE;
	};
}

function move_file(finfo: Files::Info)
	{
	local ex_file = finfo$extracted;
	local ex_path = cat(FileExtract::prefix, ex_file);
	local pre_path = cat(preserve_prefix, ex_file);

	# Move files using mv
	local ret = system(fmt("mv \"%s\" \"%s\"",
		safe_shell_quote(ex_path),
		safe_shell_quote(pre_path)
		));

	finfo$preserve_state = FILE_MOVED;
	}

function preserve_match(s: Seen)
	{
	# Skip if observed type is not of interest
	if ( (|preserve_filter| != 0) && # keep all by default
		 (s$indicator_type !in preserve_filter) )
		return;

	# Hit in the context of a file
	if( s?$f )
		{
		local fuid = s$f$info$fuid;
		# Check whether file analysis is ongoing
		if ( Files::file_exists(fuid) )
			{
			# Mark file for moving after analysis
			local f = Files::lookup_file(s$f$info$fuid);
			f$info$preserve_state = KEEP_FILE;
			}
		else
			{
			# File analysis already finished
			if ( s$f$info?$extracted &&
				 (s$f$info$preserve_state != FILE_MOVED) )
				{
				move_file(s$f$info);
				}
			}
		return;
		}

	# Hit in the context of a connection
	if ( s?$conn )
		{
		# Mark connection as intel tainted
		s$conn$intel_hit = T;
		}
	}

@if ( !Cluster::is_enabled() )
event Intel::match(s: Seen, items: set[Item])
	{
	preserve_match(s);
	}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )
event Intel::match_remote(s: Seen)
	{
	preserve_match(s);
	}
@endif

event file_state_remove(f: fa_file)
	{
	if( f$info?$extracted )
		{
		if ( f$info$preserve_state == KEEP_FILE )
			{
			move_file(f$info);
			return;
			}

		for ( cid, c in f$conns )
			{
			if ( c$intel_hit )
				{
				move_file(f$info);
				return;
				}
			}
		}
	}
