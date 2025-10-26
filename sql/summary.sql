-- Provide a simple, high-level summary of the current data

show tables
;

select * from (
select
  'raw lintap' as event_type,
  elapsed: max(event_time) - min(event_time),
  uniq_process: count(distinct process_name),
  num_rows: count(*)
from
  raw_lintap_process
group by all
union by name
select
  'process' as event_type,
  elapsed: max(last_seen) - min(first_seen),
  uniq_process: count(distinct process_name),
  num_rows: count(*)
from
  process
group by all
union by name
select
  'file' as event_type,
  elapsed: max(last_seen) - min(first_seen),
  uniq_process: count(distinct process_name),
  uniq_files: count(distinct filename),
  num_rows: count(*),
from
  process_file
group by all
union by name
select
  'network' as event_type,
  elapsed: max(last_seen) - min(first_seen),
  uniq_process: count(distinct process_name),
  uniq_conn_id: count(distinct conn_id),
  uniq_local_ip: count(distinct local_ip_addr),
  uniq_remote_ip: count(distinct remote_ip_addr),
  num_rows: count(*),
from
  process_net_conn
group by all
union by name
select
  'memory' as event_type,
  elapsed: max(event_time) - min(event_time),
  uniq_process: count(distinct process_name),
  uniq_events: count(distinct source_event),
  uniq_info: count(distinct evt_info),
  num_rows: count(*),
from
  raw_lintap_memory
group by all
)
order by event_type desc
;

.print Memory summary
select source_event,
    array_to_string(list_transform(string_split(evt_info, ' '), p -> split_part(p, '=', 1)), ', ') AS keys,
       count(*) AS record_count,
      first(evt_info) AS sample_record
    FROM raw_lintap_memory
    GROUP BY all
    ORDER BY record_count DESC
;

.print Memory Flags
select source_event, REGEXP_EXTRACT(evt_info, 'flags=\d+\(([^)]+)\)', 1) AS flags_desc, count(*), count(distinct process_name)
  from raw_lintap_memory group by all 
  order by all
;

