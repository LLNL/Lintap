.print raw_lintap_memory
-- Data directly from merge_raw_tsv.sh
create or replace view raw_lintap_memory as from read_parquet(dp('raw_memory/**/*.parquet'))
;
