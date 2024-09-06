--[[
 Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 Produced at the Lawrence Livermore National Laboratory.
 All rights reserved.
--]]

-- Chisel description
description = "Summarize file IO activity every N seconds. The key for summarization is process+event+path+filename.";
short_description = "Summarize IO activity every N seconds.";
category = "Foraker";

require "common"
datafile = require("datafile")

-- Argument defaults
local interval=10
local output_path = "./data"

-- Global var for Connection Summaries for an interval
fileActivity = {}

-- Chisel argument list
args = 
{
  {
    name = "interval",
    description = "number of seconds for aggregating results. default is " .. interval .. " seconds.",
    argtype = "int",
    optional = true
  },
  {
    name = "output-path",
    description = "Directory to write output files. Default is " .. output_path .. " seconds.",
    argtype = "string",
    optional = true
  },
}

function on_set_arg(name, val)
  if name == "interval" then
    interval = parse_numeric_input(val, name)
  end
  if name == "output-path" then
    output_path = val
  end
  return true
end

function open_files(path, hostname)
  local rf_cols = table.concat({
    "file_id",
    "hostname",
    "event_count",
    "bytes_requested",
    "first_seen",
    "last_seen",
    "first_seen_ns",
    "last_seen_ns",
    "sysdig_file"}, "\t")
  pfdf = datafile.open(path, hostname, "raw_process_file", rf_cols)
  return true
end


-- Initialization callback
function on_init()
  -- Request the fields
  fname = chisel.request_field("fd.name")
  ftime = chisel.request_field("evt.time")
  frawtime = chisel.request_field("evt.rawtime")
  fbuflen = chisel.request_field("evt.buflen")
  ftype = chisel.request_field("evt.type")
  fprocname = chisel.request_field("proc.name")
  fpid = chisel.request_field("proc.pid")
  ftid = chisel.request_field("thread.tid")

  -- set the filter
  chisel.set_filter("fd.type=file and (evt.type=open or evt.type=read or evt.type=write or evt.type=close or (evt.type=unlinkat and evt.dir=<))")

  if (interval>0) then
    chisel.set_interval_s(interval)
  end

  return true
end

function on_capture_start()
  -- Get hostname
  hostname=sysdig.get_machine_info().hostname
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
  local evt_type = evt.field(ftype)
  local filename=evt.field(fname)

  local pid=evt.field(fpid)
  local tid=evt.field(ftid)
  local keyObject = {pid,tid,evt.field(fprocname),evt_type,filename}
  -- Danger! Filenames could have an embedded colon. I guess a process_name might also...
  local keyId = table.concat(keyObject,":")
  local time = evt.field(ftime)
  local rawtime=evt.field(frawtime)
  local buflen=evt.field(fbuflen)
  if buflen == nil then
    buflen=0
  end
  if fileActivity[keyId] then
    -- exists, update it
    local cur=fileActivity[keyId]
    cur.count=cur.count+1
    -- Assume events are in time order, so only update the last seen
    cur.lastSeen=time;
    cur.lastSeenNs=rawtime;
    cur.bytes=cur.bytes+buflen
  else
    -- new one, add it
    fileActivity[keyId]={count=1,bytes=buflen,firstSeen=time,lastSeen=time,firstSeenNs=rawtime,lastSeenNs=rawtime}
  end
  return true
end

function on_interval(delta)
  print("  File interval: " .. ( os.date( "%m/%d/%Y %H:%M:%S" , delta )))
  writeToCsv()
  -- Empty the fileActivity. This chisel just reports increments.
  fileActivity = {}
  if (os.time() > next_batch_epoch) then
    -- Rotate TSV files
    close_files()
    open_files(output_path, hostname)
  end
  return true
end

function on_capture_end(delta)
  print("capture end: " .. ( os.date( "%m/%d/%Y %H:%M:%S" , delta )))
  -- Write the last partial interval
  writeToCsv()
  close_files()
  return true
end

function writeToCsv()
  -- Wow, lua has no way to get the size of a table! So, we'll just count as we iterate...
  local i=0
  for key, value in pairs(fileActivity) do
    pfdf.handle:write(key)
    pfdf.handle:write("\t")
    pfdf.handle:write(hostname)
    pfdf.handle:write("\t")
    pfdf.handle:write(value.count)
    pfdf.handle:write("\t")
    pfdf.handle:write(value.bytes)
    pfdf.handle:write("\t")
    pfdf.handle:write(value.firstSeen)
    pfdf.handle:write("\t")
    pfdf.handle:write(value.lastSeen)
    pfdf.handle:write("\t")
    pfdf.handle:write(value.firstSeenNs)
    pfdf.handle:write("\t")
    pfdf.handle:write(value.lastSeenNs)
    pfdf.handle:write("\t")
    pfdf.handle:write(sysdig_file)
    pfdf.handle:write("\n")
    i=i+1
  end
  print("  File interval has " .. i .. " rows")
end

function close_files()
  datafile.close(pfdf)
end

-- Split filename on "/"
function splitPath(fqfn)
  parts = {}
  -- No split function in lua! Do it the hard way
  for w in fqfn:gmatch("([^/]+)") do
    table.insert(parts,w)
  end
  
  return parts
end

-- TODO Create a function library for this and other key functions
function getPidKey(pid)
  return hostname .. ":" .. pid
end

function getPathKey(path)
  return hostname .. ":" .. path
end