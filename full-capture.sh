# Run with rotating files, foraker filter, minimal snaplen
# Writes SCAP and executes chisel, which writes CSVs

# Define values used to name data files
hostname=`hostname -f`
timestamp=`date +"%s"`
# Defaults for datapath and dataset.
datapath=${1:-data}
dataset=${2:-lintap}
scapdir="$datapath/$dataset/scap"
scapfile="$scapdir/$hostname-$timestamp.scap"
lintappath="$datapath/$dataset"
mkdir -p $scapdir

echo "Writing SCAP files to:   $scapfile"
echo "Writing Lintap files to: $lintappath"

process_filter="((evt.type=execve and evt.dir=<) or (evt.type=clone and evt.dir=>) or (evt.type=vfork and evt.dir=<) or evt.type=procexit) or (fd.type=file and (evt.type=open or evt.type=read or evt.type=write or evt.type=close)) or (fd.l4proto=tcp or fd.l4proto=udp)" 
file_filter="fd.type=file and (evt.type=open or evt.type=read or evt.type=write or evt.type=close)"
sysdig -c fileio_agg.lua "10 $lintappath" -c ./process_events.lua $lintappath -zw $scapfile -s 8 -C 50 -F "($process_filter) or ($file_filter)"
# -c ./process_events.lua $lintappath