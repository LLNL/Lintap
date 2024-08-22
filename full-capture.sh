# Run with rotating files, foraker filter, minimal snaplen
# Writes SCAP and executes chisel, which writes CSVs
sysdig -c ./process_events.lua -zw data/acme-alpha1.scap -s 8 -C 50 -F "((evt.type=execve and evt.dir=<) or (evt.type=clone and evt.dir=>) or (evt.type=vfork and evt.dir=<) or evt.type=procexit) or (fd.type=file and (evt.type=open or evt.type=read or evt.type=write or evt.type=close)) or (fd.l4proto=tcp or fd.l4proto=udp)" 
