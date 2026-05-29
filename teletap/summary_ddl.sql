-- Provide a simple, high-level summary of the current data

.print Creating Summary View

create or replace view event_summary
as
select * from (
select
  'process' as event_type,
  first_seen: to_timestamp(min(win32_to_epoch(eventtime))),
  last_seen: to_timestamp(max(win32_to_epoch(eventtime))),
  elapsed: to_seconds(max(win32_to_epoch(eventtime)) - min(win32_to_epoch(eventtime))),
  uniq_process_name: count(distinct processname),
  uniq_pid: count(distinct pid),
  num_rows: count(*)
from
  raw_process
group by all
union by name
select
  'file' as event_type,
  first_seen: to_timestamp(min(win32_to_epoch(firstseen))),
  last_seen: to_timestamp(max(win32_to_epoch(lastseen))),
  elapsed: to_seconds(max(win32_to_epoch(lastseen)) - min(win32_to_epoch(firstseen))),
  uniq_process_name: count(distinct processname),
  uniq_pid: count(distinct pid),
  uniq_files: count(distinct file_path),
  events: sum(eventcount),
  num_rows: count(*),
from
  raw_process_file
group by all
union by name
select
  'network' as event_type,
  first_seen: to_timestamp(min(win32_to_epoch(firstseenms))),
  last_seen: to_timestamp(max(win32_to_epoch(lastseenms))),
  elapsed: to_seconds(max(win32_to_epoch(lastseenms)) - min(win32_to_epoch(firstseenms))),
  uniq_process_name: count(distinct processname),
  uniq_pid: count(distinct pid),
  uniq_conn_id: count(distinct connid),
  uniq_local_ip: count(distinct localipaddr),
  uniq_remote_ip: count(distinct remoteipaddr),
  events: sum(eventcount),
  num_rows: count(*),
from
  raw_process_conn_incr
group by all
union by name
select
  'performance' as event_type,
  first_seen: min(time),
  last_seen: max(time),
  elapsed: max(time) - min(time),
  uniq_process_name: count(distinct command),
  max_cpu: max(cpu_percent),
  max_mem: max(mem_percent),
  max_read: max(kb_read_per_sec),
  max_write: max(kb_write_per_sec),
  num_rows: count(*),
from
  pidstat_metrics
group by all
)
order by event_type desc
;


.print Creating Charting Views

create or replace view process_chart as
select
  time_chunk: time_bucket(INTERVAL 10 seconds, to_timestamp(win32_to_epoch(eventtime))),
  event_type: 'process',
  uniq_process_name: count(distinct processname),
  uniq_pid: count(distinct pid),
  num_rows: count(*)
from
  raw_process
group by all
order by time_chunk
;

create view file_chart as 
select
  time_chunk: time_bucket(INTERVAL 10 seconds, to_timestamp(eventtime)),
  event_type: 'file',
  uniq_process_name: count(distinct processname),
  uniq_pid: count(distinct pid),
  uniq_files: count(distinct file_path),
  events: sum(eventcount),
  num_rows: count(*),
from
  raw_process_file
group by all
order by all
;

create view network_chart as
select
  time_chunk: time_bucket(INTERVAL 10 seconds, to_timestamp(eventtime)),
  event_type: 'network',
  uniq_process_name: count(distinct processname),
  uniq_pid: count(distinct pid),
  uniq_conn_id: count(distinct connid),
  uniq_local_ip: count(distinct localipaddr),
  uniq_remote_ip: count(distinct remoteipaddr),
  events: sum(eventcount),
  num_rows: count(*),
from
  raw_process_conn_incr
group by all
order by time_chunk
;

create view perf_chart as 
select
  time_bucket(INTERVAL 10 seconds, time) time_chunk,
  'performance' as event_type,
  uniq_process_name: count(distinct command),
  max_cpu: max(cpu_percent),
  max_mem: max(mem_percent),
  max_read: max(kb_read_per_sec),
  max_write: max(kb_write_per_sec),
  num_rows: count(*),
from
  pidstat_metrics
group by all
order by all
;


