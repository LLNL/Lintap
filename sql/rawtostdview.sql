/*
Convert from LINTAP RAW data (from merge_raw_tsv.sh) to Wintap RAW.

This script supports:

RAW_PROCESS
RAW_PROCESS_FILE
 */

-- Macros are used to define constants for the data paths. Modify this path as needed.
-- parquet_def should be one of these forms:
--   raw_process/**/*.parquet
--   process.parquet
create or replace macro dp(parquet_def)
as
concat_ws('/','data/lintap/raw_sensor',parquet_def)
;

-- From initdb.sql
create or replace macro to_timestamp_micros(es)
as to_timestamp(cast(floor(es) as bigint)) + to_microseconds(cast(floor((es - floor(es)) * 1e6) as bigint))
;

-- FileID
-- Assume filesystem case-sensitive
create or replace macro gen_file_id(hostname, filename)
as md5(concat_ws('||', hostname, filename))
;

-- Data directly from merge_raw_tsv.sh
create or replace table raw_lintap_process as from read_parquet(dp('raw_process/**/*.parquet'))
;
-- Derive features used for creating and debugging PID_HASH
-- To Do: Consider moving these derived values into the merge_raw_tsv.sh script
create or replace table lintap_process
as 
select * exclude (pid_key),
  naive_start_time: first_value(event_time) over pid_events,
  prior_event: lag(source_event, 1, 'first event') over pid_events,
  prior_process_name: lag(process_name, 1, 'first event') over pid_events,
  elapsed: event_time - lag(event_time, 1, null) over pid_events,
  name_change: process_name <> lag(process_name, 1, process_name) over pid_events,
  pid_key: concat_ws(':', hostname, process_name, ospid, parentpid, naive_start_time),
  -- TODO: Add a running total based on this value. The result *should* be a consistent value over the events between a START/EXIT and useable as a partition key in a subsequent query to breakup "re-used" PIDs.
  -- Note: Putting this off as it appears there really aren't many of these cases. See "Summary of Naive" and look at the "num_process" field.
  new_process: if(prior_event='procexit >',1,0),
from (select *, num_dups: count(*) from raw_lintap_process group by all)
window pid_events as (partition by hostname, process_name, ospid, parentpid order by event_time)
;

-- Now map to raw_process. From here, we can leverage the existing raw_to_stdview sql.
create or replace view raw_process
as
SELECT
	Hostname,
	null agentid,
	'calcme' ParentPidHash,
	ParentPid,
	ospid PID,
	md5(pid_key) PidHash,
	process_name ProcessName,
	exe ProcessPath,
	naive_start_time StartTime,
	'missing' FileMd5,
	'missing' FileSha2,
	UserName,
	args ProcessArgs,
	epoch_us(event_time)/1e6 EventTime,
	'PROCESS' MessageType,
	case
		when source_event='thread table' then 'refresh'
		when source_event='execve <' then 'start'
		when source_event='vfork <' then 'start'
		when source_event='clone >' then 'start'
		when source_event='procexit >' then 'stop'
		else source_event
	end	ActivityType,
	process_name||' '||args CommandLine,
	'tbd' UniqueProcessKey,
	dayPK,
	null hourPK,
	count(*) num_dups
FROM
	lintap_process
group by all
;

CREATE OR REPLACE TABLE process
AS
SELECT
    p.pidhash pid_hash, -- osfamily will eventually come back as a partition key
    any_value('linux') os_family,
    any_value(agentid) agent_id,
    count(distinct agentid) num_agent_id,
    any_value(p.hostname) hostname,
    any_value(pid) os_pid,
    any_value(CASE
        WHEN p.processname = '' THEN NULL
        ELSE p.processname
    END) process_name,
    count(DISTINCT p.processname) num_process_name,
    any_value(CASE
        WHEN p.processargs = '' THEN NULL
        ELSE p.processargs
    END) args,
    count(DISTINCT p.processargs) num_args, -- Ignore useless names
    any_value(CASE
        WHEN
            p.username = ''
            OR lower(p.username) = 'na' THEN NULL
        ELSE p.username
    END) user_name,
    count(DISTINCT p.username) num_user_name,
    any_value(CASE
        WHEN p.parentpidhash = '' THEN NULL
        ELSE p.parentpidhash
    END) parent_pid_hash,
    count(DISTINCT p.parentpidhash) num_parent_pid_hash,
    any_value(p.parentpid) parent_os_pid,
    count(DISTINCT p.parentpid) num_parent_os_pid,
    any_value(CASE
        WHEN p.processpath = '' THEN NULL
        ELSE p.processpath
    END) process_path,
    -- Add empty fields that will be set in the next step
    count(DISTINCT p.processpath) num_process_path,
    '' filename,
    '' file_id,
    any_value(CASE
        WHEN p.filemd5 = '' THEN NULL
        ELSE p.filemd5
    END) file_md5,
    count(DISTINCT p.filemd5) num_file_md5,
    any_value(CASE
        WHEN p.filesha2 = '' THEN NULL
        ELSE p.filesha2
    END) file_sha2,
    count(DISTINCT p.filesha2) num_file_sha2,
    min(CASE
        WHEN
            upper(p.activitytype) IN ('START', 'REFRESH')
            THEN p.eventtime
        ELSE NULL
    END) process_started_seconds,
    min(CASE
        WHEN
            upper(p.activitytype) IN ('START', 'REFRESH')
            THEN p.starttime
        ELSE NULL
    END) process_started,
    to_timestamp(min(p.eventtime)) first_seen,
    to_timestamp(max(p.eventtime)) last_seen,
    sum((CASE WHEN upper(p.activitytype) IN ('START', 'REFRESH') THEN 1 ELSE 0 END)) num_process_start,
    -- These all come from ETW Process Stop events
    max(CASE
        WHEN
            upper(p.activitytype) IN ('STOP')
            THEN p.eventtime
        ELSE NULL
    END) process_stop_seconds,
    max(CASE
        WHEN
            upper(p.activitytype) IN ('STOP')
            THEN to_timestamp(p.eventtime)
        ELSE NULL
    END) process_term,
    sum((CASE WHEN upper(p.activitytype) = 'STOP' THEN 1 ELSE 0 END)) num_process_stop
FROM raw_process p
GROUP BY ALL
;

-- Set Parent_Pid_Hash
update process p
set parent_pid_hash=
  (select first(pid_hash order by pp.process_started) from process pp where pp.os_pid=p.parent_os_pid and pp.hostname=p.hostname)
;

-- File data
-- Data directly from merge_raw_tsv.sh
create or replace table raw_lintap_process_file as
SELECT 
  split(file_id, ':')[1] pid,
  split(file_id, ':')[2] tid,
  split(file_id, ':')[3] proc_name,
  split(file_id, ':')[4] event_type,
  split(file_id, ':')[5] filename,
  * exclude (file_id)    
from read_parquet(dp('raw_process_file/**/*.parquet'))
;

create or replace table raw_process_file
as
select
    f.filename path,
    bytes_requested bytesrequested,
    f.pid,
    case 
    	when event_type='open' then 'OPEN'
    	when event_type='openat' then 'OPEN'
    	when event_type='read' then 'READ'
    	when event_type='imjournal' then 'READ'
    	when event_type='main Q' then 'READ'
    	when event_type='write' then 'WRITE'
    	when event_type='close' then 'CLOSE'
    	when event_type='mmap' then 'CREATE'
    end activitytype,
    p.process_name processname,
    event_count eventcount,
    epoch_us(f.first_seen) firstseen,
    epoch_us(f.last_seen) lastseen,
    p.pid_hash pidhash,
    p.hostname,
    null file_hash,
    f.filename file_path,
    'FILE' messagetype,
    epoch_us(f.first_seen) eventtime,
    null agentid,
from raw_lintap_process_file f
asof join process p 
   on f.hostname=p.hostname
  and f.pid=p.os_pid
  and f.first_seen >= p.process_started
group by all
;


CREATE TABLE IF NOT EXISTS process_file
AS
SELECT
    agentid agent_id,
    hostname,
    pidhash pid_hash, -- generate FileID
    processname process_name,
    file_id: gen_file_id(hostname, file_path),
    file_hash file_hash,
    file_path filename,
    activitytype activity_type,
    sum(bytesrequested) bytes_requested,
    sum(eventcount) event_count,
    count(*) num_raw_rows,
    to_timestamp_micros((min(cast(firstseen as bigint)/1e6))) first_seen,
    to_timestamp_micros((max(cast(lastseen as bigint)/1e6))) last_seen,
    to_timestamp(min(cast(eventtime as bigint)/1e6)) min_event,
    to_timestamp(max(cast(eventtime as bigint)/1e6)) max_event
FROM raw_process_file
GROUP BY ALL
;


create or replace view process_file_summary
--# required
--# template: stdview
as
SELECT
  agent_id,
  hostname,
  process_name,
  pid_hash,
  -- Note: Delete is always 0 bytes, so, don't create a column for it.
  sum(CASE WHEN activity_type = 'CLOSE' THEN event_count ELSE 0 END) Close_Events,
  sum(CASE WHEN activity_type = 'CREATE' THEN event_count ELSE 0 END) Create_Events,
  sum(CASE WHEN activity_type = 'DELETE' THEN event_count ELSE 0 END) Delete_Events,
  sum(CASE WHEN activity_type = 'RENAME' THEN event_count ELSE 0 END) Rename_Events,
  sum(CASE WHEN activity_type = 'SETINFO' THEN event_count ELSE 0 END) SetInfo_Events,
  sum(CASE WHEN activity_type = 'READ' THEN bytes_Requested ELSE 0 END) Read_Bytes,
  sum(CASE WHEN activity_type = 'READ' THEN event_count ELSE 0 END) Read_Events,
  sum(CASE WHEN activity_type = 'WRITE' THEN bytes_Requested ELSE 0 END) Write_Bytes,
  sum(CASE WHEN activity_type = 'WRITE' THEN event_count ELSE 0 END) Write_Events,
  sum(num_raw_rows) num_raw_rows,
  count(DISTINCT file_hash) num_uniq_file_hash,
  sum(CASE WHEN filename IS NULL THEN 1 ELSE 0 END) num_null_filename,
  min(first_seen) first_seen,
  max(last_seen) last_seen
FROM process_file
GROUP BY all
;

-- Export data
--copy process to '/Users/johnson30/data/lintap/lindseyw/lintap-20250417-1/process.parquet' (format 'parquet');
--copy raw_process_file to '/Users/johnson30/data/lintap/lindseyw/lintap-20250417-1/raw_process_file.parquet' (format 'parquet');
--copy process_file to '/Users/johnson30/data/lintap/lindseyw/lintap-20250417-1/process_file.parquet' (format 'parquet');

