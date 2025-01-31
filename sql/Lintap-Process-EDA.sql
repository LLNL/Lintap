/*
  Pids are getting re-used more frequently than expected.
  TODO: Need a real stateful PIDHASH util in the sensor.
  Some QA ideas
  
  - Scatter Plot PID, time
  - Calculate a propper PIDHASH
  	- Look for dups after that: different parents/process_names/other?
  - Simulate streaming with window functions(?) then look for anomolies
  
 */

summarize raw_process

drop view lintap_process;

create or replace table lintap_process as from '/Users/johnson30/data/ACME4/lintap/raw_process/**/*.parquet'

create or replace view raw_process as from '/Users/johnson30/data/wintapv6/ACME/rolling/raw_process/**/*.parquet'

select hostname, count(DISTINCT process_name) from lintap_process group by all


create or replace view raw_process
as
SELECT
	'calcme' ParentPidHash,
	ParentPid,
	ospid PID,
	concat_ws(':',hostname, ospid, epoch) PidHash,
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
	
select source_event, count(*) from lintap_process group by all

select process_name, exe, count(*) from lintap_process where process_name != exe group by all

select num_dups, first(pidhash) example, count(*) from raw_process group by all  order by all

select * from raw_process where pidhash='guacamole.localdomain:20918:1725703734'

select * from lintap_process where pid_key='ip-172-31-13-168.us-gov-west-1.compute.internal:9889' and ParentPid =9888 order by epoch


-- Is this unique?
select
	num_names,
	num_args,
	num_times,
	count(*) num_rows,
	first(testkey) example
from
	(
	SELECT
		count(distinct process_name) num_names,
		count(distinct args) num_args,
		count(distinct event_time) num_times,
		concat_ws(':',hostname, ospid, parentpid) testkey
	from
		lintap_process
	group by
		hostname,
		ospid,
		parentpid
	order by
		all desc
)
group by
	all
order by
	num_rows desc


