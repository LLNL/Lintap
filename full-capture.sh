#!/bin/bash
# Run with rotating files, foraker filter, minimal snaplen
# Writes SCAP and executes chisel, which writes CSVs

# Define values used to name data files
hostname=`hostname -f`
timestamp=`date +"%s"`

# Default values
datapath="data"
dataset="lintap"
write_scap_flag=true

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --no-scap)
      write_scap_flag=false
      shift
      ;;
    *)
      # Handle positional arguments
      if [[ -z "$datapath_set" ]]; then
        datapath="$1"
        datapath_set=true
      elif [[ -z "$dataset_set" ]]; then
        dataset="$1"
        dataset_set=true
      else
        echo "Unknown arg: $1"
        exit 1
      fi
      shift
      ;;
  esac
done

# Setup paths
lintappath="$datapath/$dataset"
scapdir="$datapath/$dataset/scap"
scapfile="$scapdir/$hostname-$timestamp.scap"
mkdir -p $scapdir

# Configure SCAP writing based on flag
if [ "$write_scap_flag" = true ]; then
  write_scap="-zw $scapfile -C 50"
  scap_file_msg="$scapfile"
else
  write_scap=""
  scap_file_msg="no SCAP written"
fi

echo "Writing SCAP files to:   $scap_file_msg"
echo "Writing Lintap files to: $lintappath"

# Filters for events
process_filter="((evt.type=execve and evt.dir=<) or (evt.type=clone and evt.dir=>) or (evt.type=vfork and evt.dir=<) or evt.type=procexit)" 
file_filter="fd.type=file and (evt.type=open or evt.type=openat or evt.type=read or evt.type=write or evt.type=mmap or evt.type=close  or (evt.type=unlinkat and evt.dir=<))"
network_filter="fd.l4proto=tcp or fd.l4proto=udp"
memory_filter="(
    evt.type in (brk, mmap, mmap2, munmap, mprotect, mremap, madvise, mincore,
                 mlock, munlock, mlockall, munlockall, mlock2,
                 pkey_mprotect,
                 mbind, set_mempolicy, get_mempolicy, set_mempolicy_home_node,
                 remap_file_pages,
                 map_shadow_stack,
                 cachestat
    )
    or evt.type in (process_vm_readv, process_vm_writev)
    or evt.type in (splice, vmsplice, tee) )
"

# Sysdig parameters:
#  -c [chisel] "[chisel args]"
#      Note: multiple chisel args need to be quoted so the shell treats them as a single string
#  -zw Write events to SCAP file, compressed
#  -C Rotate SCAP file at N MB
#  -s Limit bytes of buffer data captured for file io/network packets
#       Note: 8 seems to be the smallest actual size
#  -F Event filter
sysdig -c ./process_events.lua $lintappath \
  -c fileio_agg.lua "10 $lintappath" \
  -c pci_agg.lua "10 $lintappath" \
  -c memory_events.lua $lintappath \
  $write_scap \
  -s 8 -F "($process_filter) or ($file_filter) or ($network_filter) or ($memory_filter)"