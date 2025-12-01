--[[
 Copyright (c) 2024, Lawrence Livermore National Security, LLC.
 Produced at the Lawrence Livermore National Laboratory.
 All rights reserved.
--]]

-- Chisel description
description = "Write memory events. Does no aggregation";
short_description = "Monitors all memory events (there are >25)";
category = "Foraker";

--[[
Raw event example:
{
  "evt.cpu": 0,
  "evt.dir": ">",
  "evt.info": "addr=0",
  "evt.num": 2738,
  "evt.outputtime": 1761443273107487235,
  "evt.type": "brk",
  "proc.name": "vi",
  "thread.tid": 14173
}
--]]

require "common"
datafile = require("datafile")

-- Argument defaults and globals
local output_path = "./data"
local hostname = ""

-- Chisel argument list
args = 
{
  {
    name = "output-path",
    description = "Directory to write output files. Default is " .. output_path .. " seconds.",
    argtype = "string",
    optional = true
  },
  {
    name = "hostname",
    description = "Hostname the collect (SCAP) is from. Optional for live collects and required for reading from a SCAP file",
    argtype = "string",
    optional = true
  },
}

function on_set_arg(name, val)
  valid = true
  if name == "output-path" then
    output_path = val
  end
  if name == "hostname" then
    hostname = val
  end
  return valid
end

function open_files(path, hostname)
  rm_cols = table.concat({"pid_key","hostname","ospid","tid", "ppid", "process_name","evt_cpu","evt_info","event_time","raw_time","source_file","source_event"},"\t")
  rmdf = datafile.open(path, hostname, "raw_memory", rm_cols)

  return true
end

function on_init()
	-- Request the fields
  -- Human readable, with NS. Also parsable by DuckDB.
	fevttime = chisel.request_field("evt.time.iso8601")
  -- Epoch with NS fractional precision. As a backup value and sortable when ftime is still just a string.
  frawtime = chisel.request_field("evt.rawtime")
	ftype = chisel.request_field("evt.type")
  fdir = chisel.request_field("evt.dir")
  fprocname = chisel.request_field("proc.name")
  fpid = chisel.request_field("proc.pid")
  fppid = chisel.request_field("proc.ppid")
  ftid = chisel.request_field("thread.tid")
  -- Event fields
  finfo = chisel.request_field("evt.info")
  fcpu = chisel.request_field("evt.cpu")

	-- set the filter
  -- execve enter (>) has the parent process name and no attributes. 
  -- clone (<) is similar
  memory_filter=[[
    evt.type in (brk, mmap, mmap2, munmap, mprotect, mremap, madvise, mincore,
                 mlock, munlock, mlockall, munlockall, mlock2,
                 pkey_mprotect,
                 mbind, set_mempolicy, get_mempolicy, set_mempolicy_home_node,
                 remap_file_pages,
                 map_shadow_stack,
                 cachestat
    )
    or evt.type in (process_vm_readv, process_vm_writev)
    or evt.type in (splice, vmsplice, tee)
    ]]
	chisel.set_filter(memory_filter)
  
  return true
end

function on_capture_start()
  -- Get hostname
  -- Note: the get_machine_info() function doesn't return anything when reading from a SCAP file, rather than live, so abort if user didn't pass in an hostname as an argument
  if sysdig.get_machine_info().hostname ~= "" then
    hostname=sysdig.get_machine_info().hostname
  end
 
  sysdig_file=sysdig.get_evtsource_name()
  if sysdig_file=="" then 
    sysdig_file=hostname .. " live"
  end
  -- Open files for writing
  open_files(output_path, hostname)

	return true
end

-- Event parsing callback
function on_event()

  evt_type = evt.field(ftype)
  evt_time = evt.field(fevttime)
  raw_time = evt.field(frawtime)
  evt_dir = evt.field(fdir)
  src = evt_type .. " " .. evt_dir
  
  pid=evt.field(fpid)
  procname=evt.field(fprocname)
  ppid=evt.field(fppid)
  tid=evt.field(ftid)
  cpu=evt.field(fcpu)
  info=evt.field(finfo)

  -- Validation
  if tonumber(pid) == nil then
    -- Not a number
    print("Nil Pid!")
    print("Event: " .. src)
    return true
  end
  -- Foraker output
  if ppid == nil then
    print("Nil ppid on pid: " .. pid)
    print("Event: " .. src)
    return true
  end
  
  if (os.time() > next_batch_epoch) then
    -- Rotate TSV files
    close_files()
    open_files(output_path, hostname)
  end

  rmdf.handle:write(table.concat({getPidKey(pid),hostname, pid,tid,ppid,procname,cpu, info, evt_time,raw_time,sysdig_file,src},"\t"))
  rmdf.handle:write("\n")

  return true
end

function close_files()
  datafile.close(rmdf)
end

function on_capture_end()
  close_files()
end

-- TODO Create a function library for this and other key functions
function getPidKey(pid)
  return hostname .. ":" .. pid
end
