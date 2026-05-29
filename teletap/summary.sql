-- Provide a simple, high-level summary of the current data

show tables
;

select * from event_summary
;

.print Chart data
select pf.*, procs:p.num_rows, file:f.num_rows, net:n.num_rows
from perf_chart pf
left outer join process_chart p on pf.time_chunk=p.time_chunk
left outer join file_chart f on pf.time_chunk=f.time_chunk
left outer join network_chart n on pf.time_chunk=n.time_chunk
order by all