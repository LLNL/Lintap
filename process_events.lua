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

hostname=""
sysdig_file=""

-- Chisel argument list
args = 
{
  {
    name = "output-path",
    description = "Directory to write output files. Default is " .. output_path .. " seconds.",
    argtype = "string",
    optional = true
  },
}


function open_files(path, hostname)
  rp_cols = table.concat({"pid_key","hostname","ospid","tid","parentpid","process_name","args","exe","uid","username","gid","event_time","epoch","source_file","source_event"},"\t")
  prdf = datafile.open(path, hostname, "raw_process", rp_cols)
  rt_cols = table.concat({"type","tid_key","pid","tid","process_name","event_time","epoch","source_file","source_event"},"\t")
  ptdf = datafile.open(path, hostname, "raw_thread", rt_cols)
  return true
end

function on_set_arg(name, val)
  if name == "output-path" then
    output_path = val
    print(val)
  end
  return true
end

function set_datatime()
  -- Set times used for data file naming
  local batch_epoch=os.time()
  local cur_hour=batch_epoch - (batch_epoch %5)
  next_batch_epoch=cur_hour+5
  return true
end


-- Initialization callback
function on_init()
  set_datatime()
	-- Request the fields
	ftime = chisel.request_field("evt.time")
  frawtime = chisel.request_field("evt.rawtime")
  fepoch = chisel.request_field("evt.rawtime.s")
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
  hostname=sysdig.get_machine_info().hostname

  sysdig_file=sysdig.get_evtsource_name()
  if sysdig_file=="" then 
    sysdig_file=hostname .. " live"
  end

  print("Hostname: " .. hostname .. "  Sysdig source: " .. sysdig_file)
  -- Open files for writing
  open_files(output_path, hostname)

  --  existing_processes = sysdig.get_thread_table(sysdig.get_filter())
  -- Get all processes/threads that exist when starting
  -- See: https://github.com/draios/sysdig/wiki/Sysdig-Chisel-API-Reference-Manual
  existing_processes = sysdig.get_thread_table()
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
    -- Process events only
      prdf.handle:write(table.concat({getPidKey(pi.pid),hostname, pi.pid,pi.tid,pi.ptid,pi.comm,args,pi.exe,pi.uid,pi.username,pi.gid,"",0,sysdig_file,"thread table"},"\t"))
      prdf.handle:write("\n")
      -- Include the main process thread in the thread table
      ptdf.handle:write(table.concat({"process",getPidKey(pi.tid),pi.pid,tid,pi.comm,"",0,sysdig_file,"thread table"},"\t"))
      ptdf.handle:write("\n")
    else
      -- Secondary threads only 
      ptdf.handle:write(table.concat({"thread",getPidKey(pi.tid),pi.pid,tid,pi.comm,"",0,sysdig_file,"thread table"},"\t"))
      ptdf.handle:write("\n")
    end
  end

	return true
end

-- Event parsing callback
function on_event()

  evt_type = evt.field(ftype)
	time = evt.field(ftime)
  epoch=evt.field(fepoch)
  -- Don't set first seen for procexit.
  if (evt.type~="procexit") then
    everest_time=os.date("%m/%d/%Y %H:%M:%S",epoch)
  else 
    everest_time=""
  end
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
    prdf.handle:write(table.concat({getPidKey(pid),hostname, pid,tid,ppid,procname,args,"",evt.field(fuid),user,evt.field(fgid),everest_time,epoch,sysdig_file,src},"\t"))
    prdf.handle:write("\n")

    ptdf.handle:write(table.concat({"process",getPidKey(tid),pid,tid,procname,everest_time,epoch,sysdig_file,src},"\t"))
    ptdf.handle:write("\n")
  else
    ptdf.handle:write(table.concat({"thread",getPidKey(tid),pid,tid,procname,everest_time,epoch,sysdig_file,src},"\t"))
    ptdf.handle:write("\n")
  end
	return true
end

function close_files()
  prdf.handle:close()
  ptdf.handle:close()
end

function on_capture_end()
  prdf.handle:close()
  ptdf.handle:close()
end

-- TODO Create a function library for this and other key functions
function getPidKey(pid)
  return hostname .. ":" .. pid
end
