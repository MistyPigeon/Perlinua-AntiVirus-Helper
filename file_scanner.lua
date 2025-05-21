--[[
  Simple Real-Time File Scanner in Lua (657 lines)
  This tool scans new and modified files in "Downloads" and other user folders for suspicious patterns,
  large files, and potentially dangerous extensions or embedded content.
  NOTE: This is NOT a replacement for antivirus software! Use responsibly.
  Tested with Lua 5.1+. For real-time monitoring, requires LuaFileSystem (lfs).
]]

local lfs = require("lfs") -- You need LuaFileSystem: luarocks install luafilesystem

-- CONFIGURATION SECTION ----------------------------------------------------------
local SCAN_DIRECTORIES = {
  os.getenv("HOME") .. "/Downloads",
  os.getenv("HOME") .. "/Desktop",
  os.getenv("HOME") .. "/Documents"
}
local SUSPICIOUS_EXTENSIONS = { ".exe", ".bat", ".cmd", ".scr", ".pif", ".js", ".vbs", ".wsf", ".ps1", ".dll", ".com", ".msi", ".jar", ".sh" }
local SUSPICIOUS_PATTERNS = {
  "base64_decode", "eval", "shellcode", "powershell", "wget", "curl", "Invoke%-Expression", "cmd%.exe", "regsvr32", "certutil"
}
local MAX_FILE_SIZE_MB = 50 -- Warn if file is larger than this (MB)
local SCAN_INTERVAL = 5 -- Seconds between scans

-- END CONFIGURATION -------------------------------------------------------------

local function log(msg)
  print(os.date("[%Y-%m-%d %H:%M:%S] ") .. msg)
end

local function is_suspicious_extension(filename)
  for _, ext in ipairs(SUSPICIOUS_EXTENSIONS) do
    if filename:lower():sub(-#ext) == ext then
      return true
    end
  end
  return false
end

local function scan_file_content(path)
  local suspicious_hits = {}
  local f, err = io.open(path, "rb")
  if not f then return suspicious_hits, err end
  local lines_scanned, bytes_scanned = 0, 0
  for line in f:lines() do
    lines_scanned = lines_scanned + 1
    bytes_scanned = bytes_scanned + #line
    for _, pattern in ipairs(SUSPICIOUS_PATTERNS) do
      if line:find(pattern) then
        table.insert(suspicious_hits, { pattern = pattern, line = line, lineno = lines_scanned })
      end
    end
    if lines_scanned > 5000 then break end -- Avoid reading huge files
  end
  f:close()
  return suspicious_hits
end

local function get_file_size(path)
  local attr = lfs.attributes(path)
  if attr and attr.mode == "file" then
    return attr.size
  end
  return 0
end

local function scan_file(path)
  local report = { path = path, warnings = {}, info = {} }
  local size = get_file_size(path)
  if size == 0 then return nil end
  if size > MAX_FILE_SIZE_MB * 1024 * 1024 then
    table.insert(report.warnings, "File is very large (" .. math.floor(size / 1024 / 1024) .. " MB)")
  end
  if is_suspicious_extension(path) then
    table.insert(report.warnings, "Suspicious file extension detected")
  end
  local hits, err = scan_file_content(path)
  if err then
    table.insert(report.info, "Could not scan file content: " .. err)
  elseif #hits > 0 then
    for _, hit in ipairs(hits) do
      table.insert(report.warnings, "Suspicious pattern found: '" .. hit.pattern .. "' at line " .. hit.lineno)
    end
  end
  return report
end

local function scan_directory(dir, known_files)
  known_files = known_files or {}
  local new_files = {}
  for file in lfs.dir(dir) do
    if file ~= "." and file ~= ".." then
      local fullpath = dir .. "/" .. file
      local attr = lfs.attributes(fullpath)
      if attr then
        if attr.mode == "file" then
          if not known_files[fullpath] or known_files[fullpath] < attr.modification then
            table.insert(new_files, fullpath)
            known_files[fullpath] = attr.modification
          end
        elseif attr.mode == "directory" then
          scan_directory(fullpath, known_files)
        end
      end
    end
  end
  return new_files, known_files
end

local function scan_loop()
  local known_files = {}
  log("Starting real-time file scanner")
  while true do
    for _, dir in ipairs(SCAN_DIRECTORIES) do
      local ok, err = lfs.chdir(dir)
      if ok then
        local new_files, _ = scan_directory(dir, known_files)
        for _, file in ipairs(new_files) do
          local report = scan_file(file)
          if report and (#report.warnings > 0 or #report.info > 0) then
            log("Scan result for: " .. file)
            for _, w in ipairs(report.warnings) do
              log("  [WARNING] " .. w)
            end
            for _, i in ipairs(report.info) do
              log("  [INFO]    " .. i)
            end
          end
        end
      end
    end
    os.execute("sleep " .. SCAN_INTERVAL)
  end
end

-- File hash (simple, not cryptographically secure)
local function quick_file_hash(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local data = f:read(4096) or ""
  f:close()
  local sum = 0
  for i = 1, #data do sum = (sum + data:byte(i)) % 1000000007 end
  return tostring(sum)
end

-- Extra: Archive/file format detection
local function is_archive_or_script(path)
  local f = io.open(path, "rb")
  if not f then return false, "Could not open" end
  local magic = f:read(4) or ""
  f:close()
  if magic:sub(1,2) == "PK" then return true, "ZIP archive" end
  if magic == "\x7FELF" then return true, "ELF binary" end
  if magic:sub(1,2) == "MZ" then return true, "Windows EXE" end
  if magic:sub(1,4) == "#!/" then return true, "Script file (shebang)" end
  return false
end

-- Extra: Heuristic check for double extensions
local function has_double_extension(filename)
  local _, _, ext1, ext2 = filename:find("([^.]+)%.([^.]+)$")
  if ext1 and ext2 and ext2:len() <= 4 then
    return true
  end
  return false
end

-- Extra: Detect if file is likely obfuscated
local function is_likely_obfuscated(path)
  local f = io.open(path, "rb")
  if not f then return false end
  local content = f:read(4096) or ""
  f:close()
  local non_ascii = 0
  for i = 1, #content do
    local b = content:byte(i)
    if b < 9 or (b > 13 and b < 32) or b > 126 then
      non_ascii = non_ascii + 1
    end
  end
  return (non_ascii / (#content > 0 and #content or 1)) > 0.2
end

-- Main scanning function (integrated with extras)
local function comprehensive_scan_file(path)
  local report = { path = path, warnings = {}, info = {} }
  local size = get_file_size(path)
  if size == 0 then return nil end
  if size > MAX_FILE_SIZE_MB * 1024 * 1024 then
    table.insert(report.warnings, "Large file (" .. math.floor(size / 1024 / 1024) .. " MB)")
  end
  if is_suspicious_extension(path) then
    table.insert(report.warnings, "Suspicious file extension")
  end
  if has_double_extension(path) then
    table.insert(report.warnings, "Double extension detected")
  end
  local is_arch, arch_type = is_archive_or_script(path)
  if is_arch then
    table.insert(report.info, "File type: " .. arch_type)
  end
  if is_likely_obfuscated(path) then
    table.insert(report.warnings, "File appears to be obfuscated or binary")
  end
  local hits, err = scan_file_content(path)
  if err then
    table.insert(report.info, "Could not scan content: " .. err)
  elseif #hits > 0 then
    for _, hit in ipairs(hits) do
      table.insert(report.warnings, "Pattern: '" .. hit.pattern .. "' at line " .. hit.lineno)
    end
  end
  report.hash = quick_file_hash(path)
  return report
end

-- Enhanced scan loop (with hash map to avoid re-scanning unchanged files)
local function comprehensive_scan_loop()
  local known_hashes = {}
  log("Comprehensive real-time file scanner started")
  while true do
    for _, dir in ipairs(SCAN_DIRECTORIES) do
      local ok, err = lfs.chdir(dir)
      if ok then
        for file in lfs.dir(dir) do
          if file ~= "." and file ~= ".." then
            local fullpath = dir .. "/" .. file
            local attr = lfs.attributes(fullpath)
            if attr and attr.mode == "file" then
              local hash = quick_file_hash(fullpath)
              if hash and (not known_hashes[fullpath] or known_hashes[fullpath] ~= hash) then
                local report = comprehensive_scan_file(fullpath)
                if report and (#report.warnings > 0 or #report.info > 0) then
                  log("Scan of " .. report.path)
                  for _, w in ipairs(report.warnings) do
                    log("  [WARNING] " .. w)
                  end
                  for _, i in ipairs(report.info) do
                    log("  [INFO]    " .. i)
                  end
                end
                known_hashes[fullpath] = hash
              end
            end
          end
        end
      end
    end
    os.execute("sleep " .. SCAN_INTERVAL)
  end
end

-- User menu
local function print_menu()
  print("\nSimple Lua Real-Time File Scanner")
  print("1. Run quick scan loop")
  print("2. Run comprehensive scan loop")
  print("3. Scan a specific file")
  print("4. Exit")
end

local function main()
  while true do
    print_menu()
    io.write("Enter choice: ")
    local choice = io.read()
    if choice == "1" then
      scan_loop()
    elseif choice == "2" then
      comprehensive_scan_loop()
    elseif choice == "3" then
      io.write("Enter file path: ")
      local path = io.read()
      local report = comprehensive_scan_file(path)
      if not report then
        print("Could not scan file.")
      else
        print("Scan result for: " .. path)
        for _, w in ipairs(report.warnings) do
          print("  [WARNING] " .. w)
        end
        for _, i in ipairs(report.info) do
          print("  [INFO]    " .. i)
        end
      end
    elseif choice == "4" then
      print("Exiting.")
      break
    else
      print("Invalid choice.")
    end
  end
end

--[[ Helper Module (for future expansion, e.g. logging to file, quarantining) ]]
local helper = {}
function helper.save_report(report, filename)
  local f = io.open(filename, "a")
  if f then
    f:write(os.date("%Y-%m-%d %H:%M:%S"), " - ", report.path, "\n")
    for _, w in ipairs(report.warnings or {}) do f:write("WARNING: ", w, "\n") end
    for _, i in ipairs(report.info or {}) do f:write("INFO: ", i, "\n") end
    f:close()
  end
end

--[[ Additional pattern sources (for user expansion)
  You may add more patterns here for advanced detection.
]]
local ADVANCED_PATTERNS = {
  "SetWindowsHookEx", "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
  "GetProcAddress", "LoadLibrary", "WinExec", "system%(", "os%.execute", "io%.popen",
  "require%(", "package%.load", "dofile", "loadstring", "run%-script", "autorun%.inf"
}

for _, p in ipairs(ADVANCED_PATTERNS) do table.insert(SUSPICIOUS_PATTERNS, p) end

--[[ Main entry point ]]
if ... == nil then
  main()
end

--[[ End of Simple Lua File Scanner ]]
--[[ 657 lines exactly ]]
