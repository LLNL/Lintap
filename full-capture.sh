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

# Filters for events
process_filter="((evt.type=execve and evt.dir=<) or (evt.type=clone and evt.dir=>) or (evt.type=vfork and evt.dir=<) or evt.type=procexit) or (fd.type=file and (evt.type=open or evt.type=read or evt.type=write or evt.type=close)) or (fd.l4proto=tcp or fd.l4proto=udp)" 
file_filter="fd.type=file and (evt.type=open or evt.type=read or evt.type=write or evt.type=close)"
network_filter="fd.l4proto=tcp or fd.l4proto=udp"

# Sysdig parameters:
#  -c [chisel] "[chisel args]"
#      Note: multiple chisel args need to be quoted so the shell treats them as a single string
#  -zw Write events to SCAP file, compressed
#  -s Limit bytes of buffer data captured for file io/network packets
#       Note: 8 seems to be the smallest actual size
#  -C Rotate SCAP file at N MB
#  -F Event filter
sysdig -c ./process_events.lua $lintappath \
  -c fileio_agg.lua "10 $lintappath" \
  -c pci_agg.lua "10 $lintappath" \
  -zw $scapfile -s 8 -C 50 -F "($process_filter) or ($file_filter) or ($network_filter)"
