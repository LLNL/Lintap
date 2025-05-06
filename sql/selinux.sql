/*
Convert from LINTAP RAW data (from merge_raw_tsv.sh) to Wintap RAW.

Currently supports:

RAW_LINTAP_SELINUX_CONTEXTS
RAW_LINTAP_SELINUX_PATHS

Requires: 

PROCESS
RAW_PROCESS_FILE

 */

-- From initdb.sql
create or replace macro to_timestamp_micros(es)
as to_timestamp(cast(floor(es) as bigint)) + to_microseconds(cast(floor((es - floor(es)) * 1e6) as bigint))
;

create or replace macro to_ts(et)
  -- Adjust to UTC. Note: this is a guess! 
as
case 
  when len(et)<=17 then
	  -- Assume its in epoch with some fractional seconds. Pad to fixed width for microseconds.
  	  -- Examples: 1745362597.194 becomes 1745362597194000
  	  -- Creates a Timestamp which is GMT-7, but Process_File is a Timestamp With Timezone (offset? 7?).
      -- To get times aligned (I think), subtract from SeLinux time.
	  make_timestamp(replace(rpad(et,17,'0'),'.','')::bigint) - INTERVAL '7 hours'
  when len(et)>=19 then
  	  -- String format: 2025-03-28 14:20:21
  	  et::timestamp
end
;

create or replace macro path_type(filename)
as
case 
  	when filename in ('.','..') then 'dir-dots'
  	when filename like ('/proc/%') then '/proc'
  	when filename not like '%/%' then 'no path'
  	when filename like '/%' and filename not like '%/' then 'fully qualified filename'
  	when filename like '/%' and filename like '%/' then 'fully qualified dir'
  	when filename not like '/%' and filename like '%/' then 'relative dir'
  	when filename not like '/%' and filename like '%/%' then 'relative-path'  	
end
;


-- Data directly from merge_raw_tsv.sh
create or replace table raw_selinux_contexts 
as 
select 
  event_time: to_ts(event_time),
  * exclude (event_time),
  num_dups: count(*)
from read_parquet(dp('raw_selinux_contexts/**/*.parquet'))
group by all
;

-- Data directly from merge_raw_tsv.sh
create or replace table raw_selinux_paths
as 
select 
  event_time: to_ts(event_time),
  -- Fix double slash. These seem to all be relative path types.
  filename: replace(filename,'//','/'),
  * exclude (event_time, filename),
  path_type: path_type(filename),
  num_dups: count(*)
from read_parquet(dp('raw_selinux_paths/**/*.parquet'))
group by all
;


-- Create a summary by host+filename. This will be used to join to lintap data.
create or replace table selinux_files
as
select
	hostname,
	filename,
	audit_id,
	path_type,
	context: mode(selinux_context),
	num_contexts: count(distinct selinux_context),
	owner: mode(owner),
	num_owner: count(distinct owner),
	group_name: mode("group"),
	num_group: count(distinct "group"),
	first_seen: min(event_time),
	last_seen: max(event_time),
	num_dups: sum(num_dups)
from raw_selinux_paths
group by all
;

/**
Confidence level: High
Known issues:
  Lintap event data seems to be off by TZ (7 hours). Confirm thats consistent across all data and fix! Or is it auditd thats off? One of them...
  Auditd collects continuously from ansible load, while Lintap is run intervals. 
     Implement a way to identify Lintap intervals, then filter audit to the interval(s) found. Implement the filter very low, like when defining the RAW_SELINUX_ tables.
  As of now, ~40% RAW rows don't join to a Lintap process, but of those 40% rows, 90% of them are attributed to just a few PIDs.
     See queries in lintap_eda.sql that break that down.
     Try binning those missing rows by time and see if they fall outside the Lintap collect...
**/
create or replace table process_selinux_contexts
as
SELECT 
	p.pid_hash,
    p.process_started,
    p.hostname,
    p.process_name,
    p.os_pid,
    p.user_name,
    rsc.* exclude (hostname, pid, src_filename),
    -- These are down here just to put them as the last columns.
    p.* exclude (pid_hash,process_started,hostname,process_name,os_pid,user_name)
FROM
    raw_selinux_contexts rsc
ASOF JOIN
    process p
    ON p.os_pid = rsc.pid
    AND p.hostname = rsc.hostname
    -- Hmm, process_started is off by 7.
    AND rsc.event_time >= (p.process_started - INTERVAL '7 hours' - INTERVAL '100 millisecond')
;


-------- Context Paths (File activity)
create or replace table process_file_selinux
as
select
  c.pid_hash,
  c.process_name,
  c.process_started,
  c.os_pid,
  file_id: gen_file_id(r.hostname, r.filename),
  r.* exclude (src_filename, daypk)
from raw_selinux_paths r
-- Join to PSC to bring in the PID_HASH
join process_selinux_contexts c on r.hostname=c.hostname and r.audit_id=c.audit_id
;


--- Master list of all Contexts, with stats on usage
-- Note that columns are already in Everest format
create or replace view SELINUX_CONTEXT
as
SELECT
  SELINUXCONTEXT_ID: selinux_context,
  SeLinuxContextKey_selinux_context: selinux_context,
  SeLinuxContext_selinux_context: selinux_context,
  SeLinuxContext_ctx_user: split(selinux_context,':')[1],
  SeLinuxContext_ctx_role: split(selinux_context,':')[2],
  SeLinuxContext_ctx_type: split(selinux_context,':')[3],
  SeLinuxContext_ctx_cat1: split(selinux_context,':')[4],
  SeLinuxContext_ctx_cat2: split(selinux_context,':')[5],  
  SeLinuxContext_num_processes_raw: max(SeLinuxContext_num_processes_raw),
  SeLinuxContext_num_processes: max(SeLinuxContext_num_processes),
  SeLinuxContext_num_files_raw: max(SeLinuxContext_num_files_raw),
  SeLinuxContext_num_files: max(SeLinuxContext_num_files)
from (
	SELECT
	  -- Contexts from processes
	  all_process_ctx.selinux_context,
	  SeLinuxContext_num_processes_raw: sum(num_processes_raw),
	  SeLinuxContext_num_processes: sum(num_processes),
	  SeLinuxContext_num_files_raw: 0,
	  SeLinuxContext_num_files: 0
	FROM
	(SELECT selinux_context, num_processes_raw: count(*) FROM raw_selinux_contexts group by all) all_process_ctx
	left outer join
	(select selinux_context, num_processes: count(*) from process_selinux_contexts group by all) p_ctx
	on all_process_ctx.selinux_context=p_ctx.selinux_context
	group by all
	UNION
	SELECT
	  -- Contexts from files
	  all_path_ctx.selinux_context,
	  SeLinuxContext_num_processes_raw: 0,
	  SeLinuxContext_num_processes: 0,
	  SeLinuxContext_num_files_raw: sum(num_files_raw),
	  SeLinuxContext_num_files: sum(num_files)
	FROM
	(SELECT rp.selinux_context, num_files_raw: count(*) FROM raw_selinux_paths rp group by all) all_path_ctx
	left outer join 
	(select selinux_context, num_files: count(*) from process_file_selinux group by all) pf_ctx
	on all_path_ctx.selinux_context=pf_ctx.selinux_context
	group by all
)
group by all
;

