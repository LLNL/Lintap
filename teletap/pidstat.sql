CREATE TABLE pidstat_metrics (
    time TIMESTAMP NOT NULL,
    uid INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    minflt_per_sec REAL NOT NULL,
    majflt_per_sec REAL NOT NULL,
    vsz_kb BIGINT NOT NULL,
    rss_kb BIGINT NOT NULL,
    mem_percent REAL NOT NULL,
    kb_read_per_sec REAL NOT NULL,
    kb_write_per_sec REAL NOT NULL,
    kb_cancelled_write_per_sec REAL NOT NULL,
    iodelay_ticks INTEGER NOT NULL,
    context_switch_per_sec REAL NOT NULL,
    nonvoluntary_context_switch_per_sec REAL NOT NULL,
    command VARCHAR(255) NOT NULL,
    
    PRIMARY KEY (time, pid)
);

COMMENT ON COLUMN pidstat_metrics.time IS 'Timestamp of the sample';
COMMENT ON COLUMN pidstat_metrics.uid IS 'User ID of the process owner';
COMMENT ON COLUMN pidstat_metrics.pid IS 'Process ID';
COMMENT ON COLUMN pidstat_metrics.minflt_per_sec IS 'Minor page faults per second (no disk I/O required)';
COMMENT ON COLUMN pidstat_metrics.majflt_per_sec IS 'Major page faults per second (disk I/O required)';
COMMENT ON COLUMN pidstat_metrics.vsz_kb IS 'Virtual memory size in kilobytes';
COMMENT ON COLUMN pidstat_metrics.rss_kb IS 'Resident set size (physical memory) in kilobytes';
COMMENT ON COLUMN pidstat_metrics.mem_percent IS 'Percentage of physical memory used';
COMMENT ON COLUMN pidstat_metrics.kb_read_per_sec IS 'Kilobytes read from disk per second';
COMMENT ON COLUMN pidstat_metrics.kb_write_per_sec IS 'Kilobytes written to disk per second';
COMMENT ON COLUMN pidstat_metrics.kb_cancelled_write_per_sec IS 'Kilobytes of cancelled write operations per second';
COMMENT ON COLUMN pidstat_metrics.iodelay_ticks IS 'Delay waiting for I/O in clock ticks';
COMMENT ON COLUMN pidstat_metrics.context_switch_per_sec IS 'Voluntary context switches per second';
COMMENT ON COLUMN pidstat_metrics.nonvoluntary_context_switch_per_sec IS 'Involuntary context switches per second';
COMMENT ON COLUMN pidstat_metrics.command IS 'Process command name';

CREATE INDEX idx_pidstat_time ON pidstat_metrics(time);
CREATE INDEX idx_pidstat_pid ON pidstat_metrics(pid);
CREATE INDEX idx_pidstat_command ON pidstat_metrics(command);
