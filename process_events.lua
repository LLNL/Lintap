--[[
 Copyright (c) 2024, Lawrence Livermore National Security, LLC.
 Produced at the Lawrence Livermore National Laboratory.
 All rights reserved.
--]]

-- Chisel description
description = "Write process lifecycle events as foraker format. Does no aggregation";
short_description = "Extract process creation (execve) and termination (procexit). On startup, optionally grab sysdigs table of existing processes.";
category = "Foraker";

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
  rp_cols = table.concat({"pid_key","hostname","ospid","tid","parentpid","process_name","args","exe","uid","username","gid","event_time","raw_time","source_file","source_event"},"\t")
  prdf = datafile.open(path, hostname, "raw_process", rp_cols)
  rt_cols = table.concat({"type","tid_key","pid","tid","process_name","event_time","raw_time","source_file","source_event"},"\t")
  ptdf = datafile.open(path, hostname, "raw_thread", rt_cols)
  return true
end

-- Initialization callback
function on_init()
	-- Request the fields
  -- Human readable, with NS. Also parsable by DuckDB.
	fevttime = chisel.request_field("evt.time.iso8601")
  -- Epoch with NS fractional precision. As a backup value and sortable when ftime is still just a string.
  frawtime = chisel.request_field("evt.rawtime")
	ftype = chisel.request_field("evt.type")
  fdir = chisel.request_field("evt.dir")
  fprocname = chisel.request_field("proc.name")
  fargs = chisel.request_field("proc.args")
  fpid = chisel.request_field("proc.pid")
  fppid = chisel.request_field("proc.ppid")
  ftid = chisel.request_field("thread.tid")
  -- User fields
  fuid = chisel.request_field("user.uid")
  fuser = chisel.request_field("user.name")
  fgid = chisel.request_field("group.gid")
  fgroup = chisel.request_field("group.name")

	-- set the filter
  -- execve enter (>) has the parent process name and no attributes. 
  -- clone (<) is similar
  process_filter = "(evt.type=execve and evt.dir=<) or (evt.type=clone and evt.dir=>) or (evt.type=vfork and evt.dir=<) or evt.type=procexit"
	chisel.set_filter(process_filter)
  
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

  --  existing_processes = sysdig.get_thread_table(sysdig.get_filter())
  -- Get all processes/threads that exist when starting
  -- See: https://github.com/draios/sysdig/wiki/Sysdig-Chisel-API-Reference-Manual
  existing_processes = sysdig.get_thread_table()

  -- Note: As there are no timestamps in threadtable, default to OS time. 
  -- TODO: Figure out how to get/pass a time when reading from a file.
  epoch=os.time()
  start_time=os.date("%m/%d/%Y %H:%M:%S",epoch)
  for tid, pi in pairs(existing_processes) do
    if pi.args then
      -- Flatten args into a single column
      args=table.concat(pi.args," ")
    else
      args=""
    end
    if tonumber(pi.pid) == nil then
      -- Not a number
      print("String pid: " .. pi.pid)
      print("Event: " .. pi)
    end

    -- When equal, its the process.
    if (pi.tid==pi.pid) then
    -- Process events only - Note: there are no time fields in the thread table.
      prdf.handle:write(table.concat({getPidKey(pi.pid),hostname, pi.pid,pi.tid,pi.ptid,pi.comm,args,pi.exe,pi.uid,pi.username,pi.gid,start_time,epoch,sysdig_file,"thread table"},"\t"))
      prdf.handle:write("\n")
      -- Include the main process thread in the thread table
      ptdf.handle:write(table.concat({"process",getPidKey(pi.tid),pi.pid,tid,pi.comm,start_time,epoch,sysdig_file,"thread table"},"\t"))
      ptdf.handle:write("\n")
    else
      -- Secondary threads only 
      ptdf.handle:write(table.concat({"thread",getPidKey(pi.tid),pi.pid,tid,pi.comm,start_time,epoch,sysdig_file,"thread table"},"\t"))
      ptdf.handle:write("\n")
    end
  end

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
  args=evt.field(fargs)

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


  -- Yup, args can have embedded returns. Awk in particular seems to like multiline args. Replace with a space.
  if args ~= null then
    if string.find(args,"\n") then
      args=string.gsub(args,"\n"," ")
    end 
    if string.find(args,"\t") then
      args=string.gsub(args,"\t"," ")
    end
  end
  -- User values
  user=evt.field(fuser)
  if user == nil then
    user="null"
  end
  group=evt.field(fgroup)
  if group == nil then
    group="null"
  end
  
  if (os.time() > next_batch_epoch) then
    -- Rotate TSV files
    close_files()
    open_files(output_path, hostname)
  end
  
  if (tid==pid) then
    prdf.handle:write(table.concat({getPidKey(pid),hostname, pid,tid,ppid,procname,args,"",evt.field(fuid),user,evt.field(fgid),evt_time,raw_time,sysdig_file,src},"\t"))
    prdf.handle:write("\n")

    ptdf.handle:write(table.concat({"process",getPidKey(tid),pid,tid,procname,evt_time,raw_time,sysdig_file,src},"\t"))
    ptdf.handle:write("\n")
  else
    ptdf.handle:write(table.concat({"thread",getPidKey(tid),pid,tid,procname,evt_time,raw_time,sysdig_file,src},"\t"))
    ptdf.handle:write("\n")
  end
  return true
end

function close_files()
  datafile.close(prdf)
  datafile.close(ptdf)
end

function on_capture_end()
  close_files()
end

-- TODO Create a function library for this and other key functions
function getPidKey(pid)
  return hostname .. ":" .. pid
end
