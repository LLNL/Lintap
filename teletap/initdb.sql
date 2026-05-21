/*
 * Macros used as UDFs
 * 
 */

.print Creating Macros
-- Macros are used to define data paths from environment variables.
--
-- Raw sensor data is resolved from either:
--   WINTAP_RAW_SENSOR_ROOT=/path/to/parquet/raw_sensor
-- or:
--   WINTAP_DATA_ROOT=/path/to/run-root
-- which resolves raw_sensor as $WINTAP_DATA_ROOT/parquet/raw_sensor.
--
-- Pidstat data is resolved from one of:
--   PIDSTAT_DATA_PATH=/path/to/pidstat[/file-glob]
--   PIDSTAT_OUTPUT_PATH=/path/to/pidstat[/file-glob]  -- legacy alias
--   WINTAP_DATA_ROOT=/path/to/run-root                -- resolves to $WINTAP_DATA_ROOT/pidstat

create or replace macro raw_sensor_root()
as case
    when getenv('WINTAP_RAW_SENSOR_ROOT') != '' then getenv('WINTAP_RAW_SENSOR_ROOT')
    when getenv('WINTAP_DATA_ROOT') != '' then concat_ws('/', getenv('WINTAP_DATA_ROOT'), 'parquet/raw_sensor')
    else error('Set WINTAP_RAW_SENSOR_ROOT or WINTAP_DATA_ROOT before loading TeleTap raw_sensor data')
end
;

create or replace macro pidstat_data_path()
as case
    when getenv('PIDSTAT_DATA_PATH') != '' then getenv('PIDSTAT_DATA_PATH')
    when getenv('PIDSTAT_OUTPUT_PATH') != '' then getenv('PIDSTAT_OUTPUT_PATH')
    when getenv('WINTAP_DATA_ROOT') != '' then concat_ws('/', getenv('WINTAP_DATA_ROOT'), 'pidstat')
    else error('Set PIDSTAT_DATA_PATH or WINTAP_DATA_ROOT before loading pidstat data')
end
;

create or replace macro csv_glob(path_def)
as case
    when contains(path_def, '*') then path_def
    else concat_ws('/', path_def, '*.csv')
end
;

-- parquet_def should be one of these forms:
--   raw_process/**/*.parquet
--   process.parquet
create or replace macro dp(parquet_def)
as
concat_ws('/', raw_sensor_root(), parquet_def)
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
