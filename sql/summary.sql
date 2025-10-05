-- Provide a simple, high-level summary of the current data

show tables
;

select * from (
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
)
order by event_type desc
;
