create table raw_process
as
from read_parquet(dp('raw_process/**/*.parquet'),union_by_name=true)
;

create table raw_process_file
as
from read_parquet(dp('raw_process_file/**/*.parquet'),union_by_name=true)
;

create table raw_process_conn_incr
as
from read_parquet(dp('raw_process_conn_incr/**/*.parquet'),union_by_name=true)
;
