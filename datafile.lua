-- Module name
require "common"

local datafile = {}

local function set_datatime()
  -- Set times used for data file naming
  epoch=os.time()
  daypk=os.date("%Y%m%d")
  local cur_hour=epoch - (epoch % 30)
  next_batch_epoch = cur_hour+30
  print(string.format("Set next batch to: %s (%s)",os.date("%m/%d/%Y %H:%M:%S",next_batch_epoch), next_batch_epoch))
  return true
end

function datafile.create_directory(dir_name)
  local success, err = os.execute("mkdir -p " .. dir_name)
  if not success then
      print("Error creating directory: " .. err)
  else
      print("Directory created successfully: " .. dir_name)
  end
  return true
end
  
function datafile.new(path, hostname, event_type, cols)
  -- Save the path
  set_datatime()
  local df = {
    fullpath=string.format("%s/raw_sensor/%s/daypk=%s", path, event_type, daypk),
    fn=string.format("%s+%s+%s.tsv", hostname, event_type, epoch),
    cols=cols
  }
  return df
end
 
function datafile.filename(df)
  return df.fullpath .. "/" .. df.fn
end
 
function datafile.activename(df)
  return datafile.filename(df) .. ".active"
end

function datafile.open(path, hostname, event_type, cols)
  df = datafile.new(path, hostname, event_type, cols)
  -- TODO: Need the path without filename here
  datafile.create_directory(df.fullpath)
  
  local handle=io.open(datafile.activename(df), "w")
  handle:write(df.cols)
  handle:write("\n")
  print("Writing to: " .. datafile.filename(df))
  df.handle=handle
  return df
end

function datafile.rename(df)
  -- Rename from ".active" basename
  local success, err = os.execute(string.format("mv %s %s", datafile.activename(df), datafile.filename(df)))
  if not success then
      print(string.format("Rename failed: %s\n\t%s",datafile.activename(df), err))
  else
      print(string.format("Renamed: %s ", datafile.activename(df)))
  end
  return true
end
  
function datafile.close(df)
  -- Close and then rename
  df.handle:close()
  datafile.rename(df)
  return true
end

return datafile

 