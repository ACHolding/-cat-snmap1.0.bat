@echo off
setlocal EnableExtensions EnableDelayedExpansion
title cat's nmap 0.1.1
set "VERSION=0.1.1"
set "TARGET="
set "PORTS="
set "TMO=400"
set "JOBS=64"
set "SHOWCLOSED="
set "KEEP="
set "PAUSE_AT_END="

rem Detect a double-click launch. Delayed expansion keeps special characters inert.
echo(!CMDCMDLINE!| find /i "/c" >nul && set "PAUSE_AT_END=1"

if /i "%~1"=="--help" goto :help
if /i "%~1"=="-?" goto :help
if "%~1"=="" goto :interactive

:parse
if "%~1"=="" goto :ready
if /i "%~1"=="-h" (
  if "%~2"=="" ( echo error: -h needs a value & goto :bad_input )
  set "TARGET=%~2"
  shift
  shift
  goto :parse
)
if /i "%~1"=="-p" (
  if "%~2"=="" ( echo error: -p needs a value & goto :bad_input )
  set "PORTS=%~2"
  shift
  shift
  goto :parse
)
if /i "%~1"=="-t" (
  if "%~2"=="" ( echo error: -t needs a value & goto :bad_input )
  set "TMO=%~2"
  shift
  shift
  goto :parse
)
if /i "%~1"=="-c" (
  if "%~2"=="" ( echo error: -c needs a value & goto :bad_input )
  set "JOBS=%~2"
  shift
  shift
  goto :parse
)
if /i "%~1"=="-a" (
  set "SHOWCLOSED=-ShowClosed"
  shift
  goto :parse
)
if /i "%~1"=="--keep" (
  set "KEEP=1"
  set "PAUSE_AT_END=1"
  shift
  goto :parse
)
if "!TARGET!"=="" (
  set "TARGET=%~1"
  shift
  goto :parse
)
echo error: unexpected argument
goto :bad_input

:interactive
echo cat's nmap %VERSION%
echo.
echo Target accepts a hostname or an IPv4 address. No http:// and no path.
echo.
set /p "TARGET=Target: "
set /p "PORTS=Ports [blank = common]: "
set "ANS="
set /p "ANS=Show closed and filtered ports? (y/N): "
if /i "!ANS!"=="y" set "SHOWCLOSED=-ShowClosed"
set "ANS="
set /p "ANS=Timeout ms [400]: "
if not "!ANS!"=="" set "TMO=!ANS!"
set "ANS="
set /p "ANS=Concurrency [64]: "
if not "!ANS!"=="" set "JOBS=!ANS!"
echo.
call :validate
if errorlevel 1 goto :bad_input
echo   target      : !TARGET!
if defined PORTS echo   ports       : !PORTS!
if not defined PORTS echo   ports       : common list
echo   timeout     : !TMO! ms
echo   concurrency : !JOBS!
echo.
set "ANS="
set /p "ANS=Start scan? (Y/n): "
if /i "!ANS!"=="n" exit /b 0
goto :ready

:ready
call :validate
if errorlevel 1 goto :bad_input
if not defined PORTS set "PORTS=21,22,23,25,53,80,110,111,135,139,143,389,443,445,587,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9200,27017"

where powershell >nul 2>nul
if errorlevel 1 (
  echo error: powershell not found
  goto :bad_input
)

rem Values reach PowerShell through environment variables, never through the command line.
set "CATNMAP_TARGET=!TARGET!"
set "CATNMAP_PORTS=!PORTS!"

set "PS=%TEMP%\catnmap_%RANDOM%%RANDOM%.ps1"
>"%PS%" echo param(
>>"%PS%" echo   [int]$TimeoutMs = 400,
>>"%PS%" echo   [int]$Jobs = 64,
>>"%PS%" echo   [switch]$ShowClosed
>>"%PS%" echo )
>>"%PS%" echo $ErrorActionPreference = 'Stop'
>>"%PS%" echo try {
>>"%PS%" echo   $Target = ([string]$env:CATNMAP_TARGET).Trim()
>>"%PS%" echo   $PortSpec = [string]$env:CATNMAP_PORTS
>>"%PS%" echo   if ($TimeoutMs -lt 1) { throw 'timeout must be at least 1 ms' }
>>"%PS%" echo   if ($Jobs -lt 1 -or $Jobs -gt 512) { throw 'jobs must be 1-512' }
>>"%PS%" echo   if ($Target.Contains(':')) { $Target = $Target.Split(':')[0] }
>>"%PS%" echo   if ($Target.Length -eq 0) { throw 'target is empty' }
>>"%PS%" echo.
>>"%PS%" echo   $ports = New-Object 'System.Collections.Generic.SortedSet[int]'
>>"%PS%" echo   foreach ($part in $PortSpec.Split(',')) {
>>"%PS%" echo     $p = $part.Trim()
>>"%PS%" echo     if ($p.Length -eq 0) { continue }
>>"%PS%" echo     $d = $p.IndexOf('-')
>>"%PS%" echo     if ($d -gt 0) {
>>"%PS%" echo       $lo = 0
>>"%PS%" echo       $hi = 0
>>"%PS%" echo       if (-not [int]::TryParse($p.Substring(0, $d), [ref]$lo)) { throw "bad range: $p" }
>>"%PS%" echo       if (-not [int]::TryParse($p.Substring($d + 1), [ref]$hi)) { throw "bad range: $p" }
>>"%PS%" echo       if ($lo -lt 1 -or $hi -gt 65535 -or $lo -gt $hi) { throw "bad range: $p" }
>>"%PS%" echo       for ($x = $lo; $x -le $hi; $x++) { [void]$ports.Add($x) }
>>"%PS%" echo     } else {
>>"%PS%" echo       $v = 0
>>"%PS%" echo       if (-not [int]::TryParse($p, [ref]$v)) { throw "bad port: $p" }
>>"%PS%" echo       if ($v -lt 1 -or $v -gt 65535) { throw "bad port: $p" }
>>"%PS%" echo       [void]$ports.Add($v)
>>"%PS%" echo     }
>>"%PS%" echo   }
>>"%PS%" echo   if ($ports.Count -eq 0) { throw 'no ports given' }
>>"%PS%" echo.
>>"%PS%" echo   $ip = $null
>>"%PS%" echo   if ($Target -cmatch '\A[0-9]{1,3}(\.[0-9]{1,3}){3}\z') {
>>"%PS%" echo     try { $ip = [System.Net.IPAddress]::Parse($Target) } catch { throw "invalid IPv4 address: $Target" }
>>"%PS%" echo   } else {
>>"%PS%" echo     try { $addrs = [System.Net.Dns]::GetHostAddresses($Target) } catch { throw ("cannot resolve '{0}': {1}" -f $Target, $_.Exception.Message) }
>>"%PS%" echo     foreach ($a in $addrs) { if ($a.AddressFamily -eq 'InterNetwork') { $ip = $a; break } }
>>"%PS%" echo     if ($null -eq $ip) { throw "no IPv4 address for '$Target'" }
>>"%PS%" echo   }
>>"%PS%" echo.
>>"%PS%" echo   $svc = @{
>>"%PS%" echo     21='ftp'; 22='ssh'; 23='telnet'; 25='smtp'; 53='domain'; 80='http'
>>"%PS%" echo     110='pop3'; 111='rpcbind'; 135='msrpc'; 139='netbios-ssn'; 143='imap'
>>"%PS%" echo     389='ldap'; 443='https'; 445='microsoft-ds'; 587='submission'
>>"%PS%" echo     993='imaps'; 995='pop3s'; 1433='ms-sql-s'; 1521='oracle'
>>"%PS%" echo     2049='nfs'; 3306='mysql'; 3389='ms-wbt-server'; 5432='postgresql'
>>"%PS%" echo     5900='vnc'; 6379='redis'; 8080='http-proxy'; 8443='https-alt'
>>"%PS%" echo     9200='elasticsearch'; 27017='mongodb'
>>"%PS%" echo   }
>>"%PS%" echo   function Svc($p) { if ($svc.ContainsKey($p)) { $svc[$p] } else { 'unknown' } }
>>"%PS%" echo.
>>"%PS%" echo   $sb = {
>>"%PS%" echo     param($ip, $port, $timeout)
>>"%PS%" echo     $sock = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
>>"%PS%" echo     try {
>>"%PS%" echo       $ar = $sock.BeginConnect((New-Object System.Net.IPEndPoint($ip, $port)), $null, $null)
>>"%PS%" echo       if ($ar.AsyncWaitHandle.WaitOne($timeout)) {
>>"%PS%" echo         $sock.EndConnect($ar)
>>"%PS%" echo         return 'open'
>>"%PS%" echo       }
>>"%PS%" echo       return 'filtered'
>>"%PS%" echo     } catch {
>>"%PS%" echo       return 'closed'
>>"%PS%" echo     } finally {
>>"%PS%" echo       $sock.Close()
>>"%PS%" echo     }
>>"%PS%" echo   }
>>"%PS%" echo.
>>"%PS%" echo   $sw = [Diagnostics.Stopwatch]::StartNew()
>>"%PS%" echo   $pool = [runspacefactory]::CreateRunspacePool(1, $Jobs)
>>"%PS%" echo   $pool.Open()
>>"%PS%" echo   $queued = @()
>>"%PS%" echo   foreach ($p in @($ports)) {
>>"%PS%" echo     $ps = [powershell]::Create()
>>"%PS%" echo     $ps.RunspacePool = $pool
>>"%PS%" echo     $null = $ps.AddScript($sb).AddArgument($ip).AddArgument($p).AddArgument($TimeoutMs)
>>"%PS%" echo     $queued += @{ PS = $ps; H = $ps.BeginInvoke(); Port = $p }
>>"%PS%" echo   }
>>"%PS%" echo.
>>"%PS%" echo   $open = @()
>>"%PS%" echo   $closed = @()
>>"%PS%" echo   $filtered = @()
>>"%PS%" echo   foreach ($j in $queued) {
>>"%PS%" echo     $st = 'closed'
>>"%PS%" echo     try { $st = [string]($j.PS.EndInvoke($j.H)[0]) } catch { $st = 'closed' }
>>"%PS%" echo     $j.PS.Dispose()
>>"%PS%" echo     if ($st -eq 'open') { $open += $j.Port }
>>"%PS%" echo     elseif ($st -eq 'filtered') { $filtered += $j.Port }
>>"%PS%" echo     else { $closed += $j.Port }
>>"%PS%" echo   }
>>"%PS%" echo   $pool.Close()
>>"%PS%" echo   $sw.Stop()
>>"%PS%" echo.
>>"%PS%" echo   Write-Host ("Nmap scan report for {0} ({1})" -f $Target, $ip)
>>"%PS%" echo   if ($open.Count -gt 0 -or $closed.Count -gt 0) { Write-Host 'Host is up.' } else { Write-Host 'Host seems down.' }
>>"%PS%" echo   $hidden = $closed.Count + $filtered.Count
>>"%PS%" echo   if (-not $ShowClosed -and $hidden -gt 0) { Write-Host ("Not shown: {0} closed or filtered tcp ports" -f $hidden) }
>>"%PS%" echo   if ($open.Count -gt 0 -or ($ShowClosed -and $hidden -gt 0)) {
>>"%PS%" echo     Write-Host ''
>>"%PS%" echo     Write-Host ("{0,-9}{1,-9}{2}" -f 'PORT', 'STATE', 'SERVICE')
>>"%PS%" echo     $o = @($open); [Array]::Sort($o)
>>"%PS%" echo     foreach ($p in $o) { Write-Host ("{0,-9}{1,-9}{2}" -f ("$p/tcp"), 'open', (Svc $p)) }
>>"%PS%" echo     if ($ShowClosed) {
>>"%PS%" echo       $c = @($closed); [Array]::Sort($c)
>>"%PS%" echo       foreach ($p in $c) { Write-Host ("{0,-9}{1,-9}{2}" -f ("$p/tcp"), 'closed', (Svc $p)) }
>>"%PS%" echo       $f = @($filtered); [Array]::Sort($f)
>>"%PS%" echo       foreach ($p in $f) { Write-Host ("{0,-9}{1,-9}{2}" -f ("$p/tcp"), 'filtered', (Svc $p)) }
>>"%PS%" echo     }
>>"%PS%" echo   }
>>"%PS%" echo   Write-Host ''
>>"%PS%" echo   Write-Host ("Nmap done: 1 IP address (1 host up) scanned in {0} seconds" -f $sw.Elapsed.TotalSeconds.ToString('0.00'))
>>"%PS%" echo } catch {
>>"%PS%" echo   Write-Host ("error: {0}" -f $_.Exception.Message)
>>"%PS%" echo   exit 2
>>"%PS%" echo }

echo Starting cat's nmap %VERSION% at %DATE% %TIME%
if defined KEEP echo engine: %PS%
powershell -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%PS%" -TimeoutMs !TMO_N! -Jobs !JOBS_N! %SHOWCLOSED%
set "RC=!ERRORLEVEL!"
if "!RC!"=="2" echo hint: check the target name and the port list
if not "!RC!"=="0" if not "!RC!"=="2" echo engine exited with code !RC!
if not defined KEEP del "%PS%" >nul 2>nul
if defined PAUSE_AT_END pause
exit /b !RC!

rem ---------------------------------------------------------------- validation
rem Every value is checked against a whitelist before it is echoed or used.
rem Values are read through delayed expansion, so ampersands, pipes and redirects in them cannot run commands.
:validate
if not defined TARGET (
  echo error: target required -h
  exit /b 1
)
echo(!TARGET!| findstr /r /x "[A-Za-z0-9.:-][A-Za-z0-9.:-]*" >nul
if errorlevel 1 (
  echo error: target may contain only letters, digits, dots, colons and dashes
  exit /b 1
)
if defined PORTS echo(!PORTS!| findstr /r /x "[-0-9, ][-0-9, ]*" >nul
if defined PORTS if errorlevel 1 (
  echo error: ports may contain only digits, commas, dashes and spaces
  exit /b 1
)
echo(!TMO!| findstr /r /x "[0-9][0-9]*" >nul
if errorlevel 1 (
  echo error: timeout must be a whole number of milliseconds
  exit /b 1
)
echo(!JOBS!| findstr /r /x "[0-9][0-9]*" >nul
if errorlevel 1 (
  echo error: concurrency must be a whole number
  exit /b 1
)
set /a "TMO_N=!TMO!" 2>nul
set /a "JOBS_N=!JOBS!" 2>nul
if !TMO_N! LSS 1 (
  echo error: timeout must be at least 1 ms
  exit /b 1
)
if !JOBS_N! LSS 1 (
  echo error: concurrency must be 1-512
  exit /b 1
)
if !JOBS_N! GTR 512 (
  echo error: concurrency must be 1-512
  exit /b 1
)
exit /b 0

:bad_input
if defined PAUSE_AT_END pause
exit /b 2

:help
echo cat's nmap %VERSION%
echo.
echo usage: nmap.bat [-h TARGET] [-p PORTS] [-t MS] [-c N] [-a] [--keep]
echo.
echo Run with no arguments for interactive prompts.
echo.
echo   -h TARGET   hostname or IPv4 (no scheme, no path)
echo   -p PORTS    comma-separated ports and ranges (default: common ports)
echo   -t MS       connect timeout in milliseconds (default 400)
echo   -c N        parallel connections, 1-512 (default 64)
echo   -a          also list closed and filtered ports
echo   --keep      keep the generated .ps1 and print its path
echo.
echo example: nmap.bat -h 127.0.0.1 -p 22,80,8000-8010 -a
if defined PAUSE_AT_END pause
exit /b 0
