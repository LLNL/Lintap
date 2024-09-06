--[[
 Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 Produced at the Lawrence Livermore National Laboratory.
 All rights reserved.
--]]

-- Chisel description
description = "Summarize TCP/UDP activity every N seconds. The key for summarization is event type+5-tuple+process.";
short_description = "Summarize TCP/UDP activity every N seconds";
category = "Foraker";

require "common"
datafile = require("datafile")

-- Argument defaults
local interval=10
local output_path = "./data"

-- Define globals
-- ToDo: https://forum.defold.com/t/how-to-create-and-use-global-constants-solved/34536

-- Delimeter for keys
keyDelim="|"
-- Connection Summaries for an interval
conntable = {}

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
  local cols = table.concat({
    "netflow_incr_key",
    "hostname",
    "count",
    "bytes",
    "first_seen.date",
    "last_seen.date",
    "first_seen_ns",
    "last_seen_ns",
    "sysdig_file"}, "\t")
  pcidf = datafile.open(path, hostname, "raw_process_conn_incr", cols)
  return true
end


-- Initialization callback
function on_init()  
  -- Request the fields
  fname = chisel.request_field("fd.name")
  fl4proto = chisel.request_field("fd.l4proto")
  ftime = chisel.request_field("evt.time")
  frawtime = chisel.request_field("evt.rawtime")
  fepoch = chisel.request_field("evt.rawtime.s")
  fbuflen = chisel.request_field("evt.buflen")
  ftype = chisel.request_field("evt.type")
  fprocname = chisel.request_field("proc.name")
  fpid = chisel.request_field("proc.pid")
  ftid = chisel.request_field("thread.tid")
  typechar = chisel.request_field("fd.typechar")

  -- set the filter
  chisel.set_filter("fd.l4proto=tcp or fd.l4proto=udp")

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
  -- Ignore non-network events
  if not evt.field(typechar)==4 then
    print("Ignoring: "..evt.field(typechar) .. "   " ..evt.field(fname))
    return true
  end
  -- Which time to use and why?
  local time = evt.field(ftime)
  local rawtime=evt.field(frawtime)
  local epoch=evt.field(fepoch)

  local conn_type = evt.field(ftype)

  local pid=evt.field(fpid)
  local tid=evt.field(ftid)
  local srcDest=splitFName(evt.field(fname))

  if (pid==nil) then
    print('Missing pid: '..evt.field(fname) ..'   '..conn_type)
    return false
  end

  if (srcDest.srcIp==nil) then
    print('Missing srcIp: '..evt.field(fname) ..'   '..conn_type)
    return false
  end
  local pciKeyObject = {pid,tid,evt.field(fprocname),evt.field(fl4proto),conn_type,srcDest.srcIp,srcDest.srcPort,srcDest.destIp,srcDest.destPort}
  -- Key for in memory increment table. Note that is is very similar to the Wintap structure:
  -- Example:
  -- tcp:write:10.217.15.170:49481->172.17.0.2:8065:mattermost:37173
  local pciKey = table.concat(pciKeyObject,keyDelim)
  local buflen=evt.field(fbuflen)
  if buflen == nil then
    buflen=0
  end
  if conntable[pciKey] then
    -- exists, update it
    local cur=conntable[pciKey]
    cur.count=cur.count+1
    -- Assume events are in time order, so only update the last seen
    cur.lastSeenNs=rawtime;
    cur.bytes=cur.bytes+buflen
  else
    -- new one, add it
    conntable[pciKey]={count=1,bytes=buflen,firstSeen=time,lastSeen=time,firstSeenNs=rawtime,lastSeenNs=rawtime}
  end
  return true
end


function on_interval(delta)
  print("  Network interval: " .. ( os.date( "%m/%d/%Y %H:%M:%S" , delta )))
  writeToCsv()
  conntable = {}
  if (os.time() > next_batch_epoch) then
    -- Rotate TSV files
    close_files()
    open_files(output_path, hostname)
  end
  return true
end

function on_capture_end(delta)
  print("Network capture end: " .. ( os.date( "%m/%d/%Y %H:%M:%S" , delta )))
  -- Write the last partial interval
  writeToCsv()
  close_files()
  return true
end

function writeToCsv()
  -- Wow, lua has no way to get the size of a table! So, we'll just count as we iterate...
  local i=0
  for key, value in pairs(conntable) do
    -- Write Foraker Model
    pcidf.handle:write(table.concat(
      {key,
      hostname,
      value.count,
      value.bytes,
      value.firstSeen,
      value.lastSeen,
      value.firstSeenNs,
      value.lastSeenNs,
      sysdig_file
      },"\t"))
    pcidf.handle:write("\n")
    i=i+1
  end
  print("  Network interval has " .. i .. " rows")
end

function close_files()
  datafile.close(pcidf)
end

-- Create 5-tuple key from the more fine-grained event key
-- Example (note the embedded dash in the process name):
--
-- udp:fstat:128.15.95.117:57629->239.255.255.250:1900:telepathy-haze:58307
--
function splitKey(eventKey)
  parts = {}
  -- No split function in lua! Do it the hard way
  -- Split on :
  for w in eventKey:gmatch("([^|]+)") do
    -- Handle the special case of the source/dest pair
    s,e = w:find("%->")
    if (s~=nil) then
      table.insert(parts,w:sub(1,s-1))
      table.insert(parts,w:sub(e+1,-1))
    else
      table.insert(parts,w)
    end
  end
  return parts
end

-- Split FName into 4-tuple source/dest.
-- Example:
--   10.217.15.170:49481->172.17.0.2:8065
function splitFName(raw)
  -- First, split on "->"
  local s,e = raw:find("%->")
  local srcIp,srcPort,destIp,destPort
  if (s~=nil) then
    srcIp,srcPort=splitIpPort(raw:sub(1,s-1))
    destIp,destPort=splitIpPort(raw:sub(e+1,-1))
--    print("Dest: "..destIp.."  "..destPort.." From: "..raw:sub(e+1,-1))
  else
    -- Hmm,its actually invalid, what to do?
    print("Invalid ftype: " .. raw)
  end
  return {srcIp=srcIp,srcPort=srcPort,destIp=destIp,destPort=destPort}
end

-- Split IP:port. Note that this also accounts for IP being an IPv6 so be careful using ':' delimiter
function splitIpPort(rawIP)
  local s,e = rawIP:find(":")
  local ip,Port
  if (s~=nil) then
    ip=rawIP:sub(1,s-1)
    port=rawIP:sub(e+1,-1)
  else 
    print("Invalid IP/Port: " .. rawIP)
  end

  return ip,port
end

-- TODO Create a function library for this and other key functions
function getPidKey(pid)
  return hostname .. ":" .. pid
end
