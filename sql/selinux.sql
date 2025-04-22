/*
Convert from LINTAP RAW data (from merge_raw_tsv.sh) to Wintap RAW.

Currently supports:

RAW_LINTAP_SELINUX_CONTEXTS
RAW_LINTAP_SELINUX_PATHS

Requires: 

PROCESS
RAW_PROCESS_FILE

 */

-- From initdb.sql
create or replace macro to_timestamp_micros(es)
as to_timestamp(cast(floor(es) as bigint)) + to_microseconds(cast(floor((es - floor(es)) * 1e6) as bigint))
;

create or replace macro to_ts(et)
as
case 
  when len(et)<=17 then
	  -- Assume its in epoch with some fractional seconds
	  make_timestamp(replace(rpad(et,17,'0'),'.','')::bigint)
  when len(et)>=19 then
  	  et::timestamp
end
;

-- Data directly from merge_raw_tsv.sh
create or replace table raw_selinux_contexts 
as 
select 
  event_time: to_ts(event_time),
  * exclude (event_time),
  num_dups: count(*)
from '/Users/johnson30/data/lintap/lindseyw/lintap-20250417-1/raw_sensor/raw_selinux_contexts/**/*.parquet'
group by all
;

-- Data directly from merge_raw_tsv.sh
create or replace table raw_selinux_paths
as 
select 
  event_time: to_ts(event_time),
  * exclude (event_time),
  num_dups: count(*)
from '/Users/johnson30/data/lintap/lindseyw/lintap-20250417-1/raw_sensor/raw_selinux_paths/**/*.parquet'
group by all
;

create view file_contexts
as
SELECT 
	p.pid_hash,
    p.process_started,
    p.hostname,
    p.process_name,
    p.os_pid,
    p.user_name,
    rf.file_path,
    rf.activitytype,
    rsc.*,
    rsp.*,
    p.* exclude (pid_hash,process_started,hostname,process_name,os_pid,user_name)
FROM
    raw_process_file rf
INNER JOIN 
    process p
    ON rf.pidhash = p.pid_hash
ASOF JOIN
    raw_selinux_contexts rsc
    ON p.os_pid = rsc.pid
    AND p.hostname = rsc.hostname
    AND rsc.event_time <= p.process_started
ASOF JOIN
    raw_selinux_paths rsp
    ON rf.file_path = rsp.filename
--    AND rf.daypk = rsp.daypk
    AND rsp.event_time <= make_timestamp(rf.firstseen)
; 

---------------
-- POSSIBLE SLURM BUG || LLNL Policy Problem
-- slurmstepd, when setting up sbatch, will place the user's script
-- in /var/spool/slurmd/jobNNNN/slurm_script
-- then selinux block user starting up the process because... 
--- node=void5 type=AVC msg=audit(1744759272.339:27510): avc:  denied  { entrypoint } for  pid=204616 comm="slurmstepd" path="/var/spool/slurmd/job02857/slurm_script" dev="dm-0" ino=1208412 scontext=user_u:user_r:user_t:s0:c3 tcontext=system_u:object_r:var_spool_t:s0 tclass=file permissive=0
--     One fix: allow use to execute_no_trans slurm scripts... except... then a user could execute other category scripts (?!)
--     Real fix: whatever is creating that file needs to preserve the file context from the source
-- ==================================================
select * from file_contexts
WHERE 
    file_path LIKE '/var/spool/slurmd/job%/slurm_script'
    AND activitytype != 'close'
ORDER BY event_time;


-- WRITE events, where process selinux context 
-- does NOT match the target file's context
-- exclude /proc for now, requires investigation.
-- Qs:
--   - why would a user be able to write to /proc?
-- ==================================================
select *,
    target_file: file_path,
    REGEXP_EXTRACT(selinux_context, 'c[0-9]+(\S+)?') AS process_selinux_category,
    REGEXP_EXTRACT(selinux_context_1, 'c[0-9]+(\S+)?') AS file_selinux_category
FROM file_contexts
WHERE 
    filename NOT LIKE '/proc/%'
--    AND CAST(rsp.timestamp AS TIMESTAMP) < rf.first_seen
    AND selinux_context LIKE '%:%:%:s%:%'
    AND target_file != '/dev/null'
    AND activitytype = 'WRITE'
    AND selinux_context IS NOT NULL
--    AND selinux_context IS NOT NULL
    AND process_selinux_category != file_selinux_category
    AND user_name != 'root'
    AND target_file NOT LIKE '%vscode%'
ORDER BY 
    hostname, os_pid, file_path;

