/*
 * Macros used as UDFs
 * 
 */

.print Creating Macros
-- Macros are used to define constants for the data paths. Modify this path as needed.
-- parquet_def should be one of these forms:
--   raw_process/**/*.parquet
--   process.parquet
create or replace macro dp(parquet_def)
as
concat_ws('/','~/data/lintap/lintap-dev/raw_sensor',parquet_def)
;

create or replace macro win32_to_epoch(wts)
as wts/1e7 - 11644473600
;

create or replace macro int_to_ip(i)
as concat_ws('.',i >> 24,i >> 16 & 255,i >> 8 & 255,i & 255)
;

create or replace macro to_timestamp_micros(es)
as to_timestamp(cast(floor(es) as bigint)) + to_microseconds(cast(floor((es - floor(es)) * 1e6) as bigint))
;
