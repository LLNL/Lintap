export DATAFILE=mydata.tsv

echo Pidstat running...
pidstat -u -d -r -w -h 2 | tail -n +2 | grep -vE '^(#|$)' |   awk -v OFS='\t' '{$1=$1; print strftime("%Y-%m-%d"), $0}' > $DATAFILE
