copy (from '/acmedata/lintap/raw_sensor/raw_process_file/**/*.tsv') to '/acmedata/testing/raw_process_file' (format parquet, per_thread_output true);

create view raw_pci as
select split(netflow_incr_key, '|') [1] pid,
    split(netflow_incr_key, '|') [2] tid,
    split(netflow_incr_key, '|') [3] process_name,
    split(netflow_incr_key, '|') [4] protocol,
    split(netflow_incr_key, '|') [5] activity_type,
    split(netflow_incr_key, '|') [6] local_ip,
    split(netflow_incr_key, '|') [7] local_port,
    split(netflow_incr_key, '|') [8] remote_ip,
    split(netflow_incr_key, '|') [9] remote_port,
    * exclude (netflow_incr_key)
from rpci