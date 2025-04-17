/*
  Pids are getting re-used more frequently than expected.
  TODO: Need a real stateful PIDHASH util in the sensor.
  Some QA ideas
  
  - Scatter Plot PID, time
  - Calculate a propper PIDHASH
  	- Look for dups after that: different parents/process_names/other?
  - Simulate streaming with window functions(?) then look for anomolies
  
 */

-- From initdb.sql
create or replace macro to_timestamp_micros(es)
as to_timestamp(cast(floor(es) as bigint)) + to_microseconds(cast(floor((es - floor(es)) * 1e6) as bigint))
;



-- Data directly from merge_raw_tsv.sh
create or replace view raw_lintap_process as from '/Users/johnson30/data/lintap/spk16/raw_sensor/raw_process/**/*.parquet';

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
  pid_key: concat_ws(':', ospid, parentpid, naive_start_time),
  -- TODO: Add a running total based on this value. The result *should* be a consistent value over the events between a START/EXIT and useable as a partition key in a subsequent query to breakup "re-used" PIDs.
  -- Note: Putting this off as it appears there really aren't many of these cases. See "Summary of Naive" and look at the "num_process" field.
  new_process: if(prior_event='procexit >',1,0),
from (select *, num_dups: count(*) from raw_lintap_process group by all)
window pid_events as (partition by ospid, parentpid order by event_time)
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
group by all;

summarize raw_process


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

update process p
set parent_pid_hash=
  (select first(pid_hash order by pp.process_started) from process pp where pp.os_pid=p.parent_os_pid )

select os_pid, concat_ws(', ',list(process_name)), list(process_started), list(process_term), count(*) from process group by all having count(*) > 1 order by all

copy process to '/Users/johnson30/data/lintap/spk16/process.parquet' (format 'parquet')

-- File data
-- Data directly from merge_raw_tsv.sh
create or replace view raw_lintap_process_file as
SELECT 
  split(file_id, ':')[1] pid,
  split(file_id, ':')[2] tid,
  split(file_id, ':')[3] proc_name,
  split(file_id, ':')[4] event_type,
  split(file_id, ':')[5] filename,
  * exclude (file_id)    
from '/Users/johnson30/data/lintap/spk16/raw_sensor/raw_process_file/**/*.parquet';

summarize raw_lintap_process_file

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
    'spk16' hostname,
    null file_hash,
    f.filename file_path,
    'FILE' messagetype,
    epoch_us(f.first_seen) eventtime,
    null agentid,
from raw_lintap_process_file f
asof join process p 
  on f.pid=p.os_pid
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
    md5(concat_ws('||', hostname, lower(file_path))) file_id,
    file_hash file_hash,
    file_path filename,
    activitytype activity_type,
    sum(bytesrequested) bytes_requested,
    sum(eventcount) event_count,
    count(*) num_raw_rows,
    to_timestamp_micros((min(cast(firstseen as bigint)))) first_seen,
    to_timestamp_micros((max(cast(lastseen as bigint)))) last_seen,
    to_timestamp(min(cast(eventtime as bigint))) min_event,
    to_timestamp(max(cast(eventtime as bigint))) max_event
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

copy raw_process_file to '/Users/johnson30/data/lintap/spk16/raw_process_file.parquet' (format 'parquet');
copy process_file to '/Users/johnson30/data/lintap/spk16/process_file.parquet' (format 'parquet');


summarize process_file_summary










select activity_type, count(*), sum(bytes_requested) from raw_process_file group by all


SELECT --pid,
 proc_name, 
  count(*)
from raw_lintap_process_file f
asof left join process p 
  on f.pid=p.os_pid
  and f.first_seen >= p.process_started
where p.os_pid is not null
group by all
order by count(*) desc
  
select count(*) from raw_lintap_process_file

select pid, count(*) from raw_lintap_process_file group by all order by count(*) desc

select * from raw_lintap_process_file



summarize process






-- Summary of Naive rollup to process. Looks pretty good!
select any_name_change, events, num_process, count(*) num_rows, example: first(pid_key) from (
	select
		pid_key,
		any_name_change: Bool_or(name_change),
		events: list(distinct source_event order by source_event),
		elapsed_stddev: stddev_pop(epoch(elapsed)),
		num_process: sum(new_process),
		num_events: count(*),
	from lintap_process 
--	where not (process_name='nessus' or args like '%nessus%')
	group by all 
--	having num_process > 0
	order by elapsed_stddev desc, count(*) desc
) group by all order by all

-- Time... sigh.
-- Source: evt.raw_time - absolute event timestamp, i.e. nanoseconds from epoch as a bigint
create or replace macro to_timestamp_micros(es)
as to_timestamp(cast(floor(es) as bigint)) + to_microseconds(cast(floor((es - floor(es)) * 1e6) as bigint))
;

select (strptime('04/16/2025 13:52:07','%m/%d/%Y %H:%M:%S')::timestamp_ns)

summarize (select make_timestamp_ns(1992, 9, 20, 13, 34, 27.123456789) ts)

summarize (select '2025-04-15T20:36:18.555555555+0000'::timestamp_ns - '2025-04-15T20:36:18.444444444+0000'::timestamp_ns diff)

select epoch(diff), date_part('microseconds',diff) from (select '2025-04-15T20:36:18.555555555+0000'::timestamp_ns - '2025-04-15T20:36:18.444444444+0000'::timestamp_ns diff)

-- Hack to fix wrong timestamp format:
  select 
    case when source_event='thread table' then
      strptime(event_time,'%m/%d/%Y %H:%M:%S')::timestamp_ns
    else
       event_time::timestamp_ns
    end event_time,



create table test as
select '2025-04-12 17:02:46.124954321'::timestamp_ns tsns

copy test to '/Users/johnson30/test.parquet' (format 'parquet')

summarize test

select to_timestamp(1744477366124900100/1e9)


/* Examples of true pid reuse
'133699:133698:1.7444773793897e+18'
 
 */
select * from lintap_process where pid_key='132166:132165:1.7444773661249e+18' order by raw_time

select * from lintap_process where ospid=133698

-- Collect summary
select min(real_time), max(real_time), count(*) from lintap_process where raw_time>0

-- How many dups?
select process_name: if(num_dups=1,'no dups',process_name), num_dups, count(*) num_rows
from lintap_process group by all order by num_rows desc, process_name
;

-- Event summary
select source_event, name_change, list(distinct num_dups) num_dups, count(*) num_rows
from lintap_process
group by all
order by all;

-- Searching for meaning in order of events. Can we detect the Beginning/End of a process?
select source_event, prior_event, name_change, count(*) num_rows, cast(null as varchar) meaning,
   example: first(concat_ws(', ', ospid, parentpid, process_name))
from lintap_process 
group by all
order by name_change,  num_rows desc
;

-- Find some examples


-- Inspect an example
select ospid, parentpid, raw_time, real_time, process_name, username, args, source_event
from lintap_process where ospid=64206 and  parentpid=64201
order by real_time
;

select ospid, parentpid, real_time, process_name, prior_process_name, username, args, source_event
from lintap_process where source_event='procexit >' and prior_event='procexit >' and  name_change order by raw_time

select min(ospid), max(ospid), count(distinct ospid), count(distinct (ospid, parentpid)) approx_process, count(*)  from lintap_process 


select num_parent, count(*), example: first(ospid) from (
	select ospid, count(distinct parentpid) num_parent from lintap_process group by all
)  group by all















create or replace table lintap_process_file as from '/Users/johnson30/data/ACME4/lintap/raw_process_file/**/*.parquet';
create or replace table lintap_process_conn_incr as from '/Users/johnson30/data/ACME4/lintap/raw_process_conn_incr/**/*.parquet';

summarize lintap_process_file



create or replace view p as 
select *,
  to_timestamp(cast(raw_time as bigint)/1e9) real_time
from read_csv('/Users/johnson30/data/lintap/lc-lindseyw/lintap/void2+raw_process+1744469649.tsv',timestampformat='%m/%d/%Y %H:%M:%S',filename=true);
summarize p;
select process_name, args, ospid, tid, parentpid, source_event, real_time from p where raw_time<>0 order by ospid, real_time;


select hostname, count(DISTINCT process_name) from lintap_process group by all

select process_name, count(*) from lintap_process where username='johnson30' group by all order by all

--- lintap_process broadly has several types of rows:
-- source_event == 'thread table'   Processes existing when sysdig started. These have no PROCESS_START
-- OSPID == TID  Process level events, initial thread
-- OSPID != TID  Threads  These are all in the "threads" table, the chisel separates them


create or replace view raw_process
as
SELECT
	'calcme' ParentPidHash,
	ParentPid,
	ospid PID,
	md5(pid_key) PidHash,
	process_name ProcessName,
	exe ProcessPath,
	event_time StartTime,
	'missing' FileMd5,
	'missing' FileSha2,
	UserName,
	args ProcessArgs,
	epoch*1^9 EventTime,
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
	Hostname,
	'tbd' UniqueProcessKey,
	dayPK,
	null hourPK,
	count(*) num_dups
FROM
	lintap_process
group by all;
	
select if(ospid==tid, 'process', 'thread') ptype, source_event, count(*) from lintap_process group by all

select process_name, exe, count(*) num_rows from lintap_process where process_name != exe group by all order by num_rows desc

--select num_dups, first(pidhash) example, count(*) from lintap_process group by all  order by all

select * from raw_process where pidhash='guacamole.localdomain:20918:1725703734'

select * from lintap_process where pid_key='ip-172-31-13-168.us-gov-west-1.compute.internal:9889' and ParentPid =9888 order by epoch


select * from lintap_process_file where pid_key='ip-172-31-13-168.us-gov-west-1.compute.internal:9889' and ParentPid =9888 order by epoch

summarize lintap_process_file

--- Split file_id back into useful parts
--- Source: pid,tid,evt.field(fprocname),evt_type,filename
SELECT 
  split(file_id, ':')[1] pid,
  split(file_id, ':')[2] tid,
  split(file_id, ':')[3] proc_name,
  split(file_id, ':')[4] event_type,
  split(file_id, ':')[5] filename,
  * exclude (file_id)    
from lintap_process_file
where hostname='ip-172-31-13-168.us-gov-west-1.compute.internal' and pid='9889'
and daypk=20240910
order by first_seen

-- Is this unique?
select
	num_times,
	num_names,
	num_args,
	count(*) num_rows,
	first(testkey) example
from
	(
	SELECT
--		count(distinct event_time) num_times,
		count(distinct real_time) num_times,
		count(distinct process_name) num_names,
		count(distinct args) num_args,
		concat_ws(':',hostname, ospid, parentpid) testkey
	from
		p
	group by
		hostname,
		ospid,
		parentpid
	order by
		all desc
)
group by all
--having num_names > num_times
order by all


-------- Experiments for subsetting by PID:
-- Example: ospid: 18155, PPID: 18154, around row 918

-- PIVOT
-- Window partition by (partial key), set START across all events, then gen a key, then group
create or replace view lp_evt_pair
as
select ospid, parentpid, real_time, process_name, username, source_event,
  prior_event: lag(source_event, 1, 'first event') over (partition by ospid, parentpid order by real_time),
  prior_process_name: lag(process_name, 1, 'first event') over (partition by ospid, parentpid order by real_time),
  elapsed: real_time - lag(real_time, 1, null) over (partition by ospid, parentpid order by real_time),
  name_change: process_name <> lag(process_name, 1, process_name) over (partition by ospid, parentpid order by real_time),
from lintap_process
--where parentpid > 5
order by all
;

-- What source_event change pairs exist? What do they mean?

create or replace table evt_pairs
as
select prior_event, source_event, name_change, count(*) num_rows, cast(null as varchar) meaning
from lp_evt_pair
group by all
order by all


select * from lp_evt_pair
where prior_event='execve <' and  source_event = 'execve <' and not name_change

select * from lintap_process where ospid=18145 and parentpid=18143

-------- Possible partial keys
hostname, ospid, parentpid, real_time

/**
select ospid, parentpid, real_time,
  list(source_event) events over (partition by ospid, parentpid, real_time,
  list({ 'source_event': source_event, 'real_time': real_time } events_times
from lintap_process
**/
