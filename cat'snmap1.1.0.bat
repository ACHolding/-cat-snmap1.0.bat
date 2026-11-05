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

rem Detect a double-click launch (cmd /c). No pipe here: a piped child has its own CMDCMDLINE that always contains /c.
set "CL=!CMDCMDLINE!"
if /i not "!CL: /c =!"=="!CL!" set "PAUSE_AT_END=1"

if "%~1"=="" goto :interactive

:parse
if "%~1"=="" goto :ready
if /i "%~1"=="--help" goto :help
if /i "%~1"=="-?" goto :help
if /i "%~1"=="/?" goto :help
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
  shift
  goto :parse
)
set "ARG=%~1"
if "!ARG:~0,1!"=="-" (
  echo error: unknown option !ARG!
  goto :bad_input
)
if defined TARGET (
  echo error: unexpected argument !ARG!
  goto :bad_input
)
set "TARGET=!ARG!"
shift
goto :parse

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
if defined PORTS (echo   ports       : !PORTS!) else (echo   ports       : common list)
echo   timeout     : !TMO_N! ms
echo   concurrency : !JOBS_N!
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
>>"%PS%" echo   function Get-Svc($n) { if ($svc.ContainsKey($n)) { $svc[$n] } else { 'unknown' } }
>>"%PS%" echo.
>>"%PS%" echo   # refused = closed, anything else that fails = filtered, success = open
>>"%PS%" echo   function Get-State($t) {
>>"%PS%" echo     if ($t.IsFaulted) {
>>"%PS%" echo       $e = $t.Exception
>>"%PS%" echo       while ($null -ne $e.InnerException) { $e = $e.InnerException }
>>"%PS%" echo       if ($e -is [System.Net.Sockets.SocketException]) {
>>"%PS%" echo         if ($e.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) { return 'closed' }
>>"%PS%" echo       }
>>"%PS%" echo       return 'filtered'
>>"%PS%" echo     }
>>"%PS%" echo     if ($t.IsCanceled) { return 'filtered' }
>>"%PS%" echo     return 'open'
>>"%PS%" echo   }
>>"%PS%" echo.
>>"%PS%" echo   $queue = New-Object 'System.Collections.Generic.Queue[int]'
>>"%PS%" echo   foreach ($n in $ports) { $queue.Enqueue($n) }
>>"%PS%" echo   $pending = New-Object 'System.Collections.Generic.List[object]'
>>"%PS%" echo   $open = New-Object 'System.Collections.Generic.List[int]'
>>"%PS%" echo   $closed = New-Object 'System.Collections.Generic.List[int]'
>>"%PS%" echo   $filtered = New-Object 'System.Collections.Generic.List[int]'
>>"%PS%" echo.
>>"%PS%" echo   $sw = [Diagnostics.Stopwatch]::StartNew()
>>"%PS%" echo   while ($queue.Count -gt 0 -or $pending.Count -gt 0) {
>>"%PS%" echo     while ($queue.Count -gt 0 -and $pending.Count -lt $Jobs) {
>>"%PS%" echo       $n = $queue.Dequeue()
>>"%PS%" echo       $c = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetwork)
>>"%PS%" echo       try {
>>"%PS%" echo         $t = $c.ConnectAsync($ip, $n)
>>"%PS%" echo         $pending.Add(@{ C = $c; T = $t; Port = $n; Born = $sw.ElapsedMilliseconds })
>>"%PS%" echo       } catch {
>>"%PS%" echo         $c.Close()
>>"%PS%" echo         $filtered.Add($n)
>>"%PS%" echo       }
>>"%PS%" echo     }
>>"%PS%" echo     $now = $sw.ElapsedMilliseconds
>>"%PS%" echo     for ($i = $pending.Count - 1; $i -ge 0; $i--) {
>>"%PS%" echo       $j = $pending[$i]
>>"%PS%" echo       $state = $null
>>"%PS%" echo       if ($j.T.IsCompleted) { $state = Get-State $j.T }
>>"%PS%" echo       elseif (($now - $j.Born) -ge $TimeoutMs) { $state = 'filtered' }
>>"%PS%" echo       if ($null -ne $state) {
>>"%PS%" echo         $j.C.Close()
>>"%PS%" echo         if ($state -eq 'open') { $open.Add($j.Port) }
>>"%PS%" echo         elseif ($state -eq 'closed') { $closed.Add($j.Port) }
>>"%PS%" echo         else { $filtered.Add($j.Port) }
>>"%PS%" echo         $pending.RemoveAt($i)
>>"%PS%" echo       }
>>"%PS%" echo     }
>>"%PS%" echo     if ($pending.Count -gt 0) { Start-Sleep -Milliseconds 2 }
>>"%PS%" echo   }
>>"%PS%" echo   $sw.Stop()
>>"%PS%" echo.
>>"%PS%" echo   $open.Sort(); $closed.Sort(); $filtered.Sort()
>>"%PS%" echo   Write-Host ("Nmap scan report for {0} ({1})" -f $Target, $ip)
>>"%PS%" echo   if ($open.Count -gt 0 -or $closed.Count -gt 0) { Write-Host 'Host is up.' } else { Write-Host 'Host seems down, or every port is filtered.' }
>>"%PS%" echo   $hidden = $closed.Count + $filtered.Count
>>"%PS%" echo   if (-not $ShowClosed -and $hidden -gt 0) { Write-Host ("Not shown: {0} closed or filtered tcp ports" -f $hidden) }
>>"%PS%" echo   if ($open.Count -gt 0 -or ($ShowClosed -and $hidden -gt 0)) {
>>"%PS%" echo     Write-Host ''
>>"%PS%" echo     Write-Host ("{0,-9}{1,-9}{2}" -f 'PORT', 'STATE', 'SERVICE')
>>"%PS%" echo     foreach ($n in $open) { Write-Host ("{0,-9}{1,-9}{2}" -f ("$n/tcp"), 'open', (Get-Svc $n)) }
>>"%PS%" echo     if ($ShowClosed) {
>>"%PS%" echo       foreach ($n in $closed) { Write-Host ("{0,-9}{1,-9}{2}" -f ("$n/tcp"), 'closed', (Get-Svc $n)) }
>>"%PS%" echo       foreach ($n in $filtered) { Write-Host ("{0,-9}{1,-9}{2}" -f ("$n/tcp"), 'filtered', (Get-Svc $n)) }
>>"%PS%" echo     }
>>"%PS%" echo   }
>>"%PS%" echo   Write-Host ''
>>"%PS%" echo   Write-Host ("Nmap done: 1 IP address scanned in {0} seconds" -f $sw.Elapsed.TotalSeconds.ToString('0.00'))
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
  echo error: target required, use -h TARGET
  exit /b 1
)
echo(!TARGET!| findstr /r /x /c:"[A-Za-z0-9.:-][A-Za-z0-9.:-]*" >nul
if errorlevel 1 (
  echo error: target may contain only letters, digits, dots, colons and dashes - no http:// and no path
  exit /b 1
)
if defined PORTS (
  rem Strip every allowed character; anything left over is illegal.
  rem findstr cannot be used here: a space inside its pattern splits it into separate patterns.
  set "CHK=!PORTS!"
  for %%C in (0 1 2 3 4 5 6 7 8 9 "," "-" " ") do set "CHK=!CHK:%%~C=!"
  if defined CHK (
    echo error: ports may contain only digits, commas, dashes and spaces
    exit /b 1
  )
)
echo(!TMO!| findstr /r /x /c:"[0-9][0-9]*" >nul
if errorlevel 1 (
  echo error: timeout must be a whole number of milliseconds
  exit /b 1
)
echo(!JOBS!| findstr /r /x /c:"[0-9][0-9]*" >nul
if errorlevel 1 (
  echo error: concurrency must be a whole number
  exit /b 1
)
rem Strip leading zeros so 08 is not read as octal, and cap the length so set /a and if cannot overflow.
call :normnum TMO
call :normnum JOBS
if not "!TMO:~9!"=="" (
  echo error: timeout is too large
  exit /b 1
)
if not "!JOBS:~9!"=="" (
  echo error: concurrency must be 1-512
  exit /b 1
)
set "TMO_N=!TMO!"
set "JOBS_N=!JOBS!"
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

:normnum
if not "!%1:~1!"=="" if "!%1:~0,1!"=="0" (
  set "%1=!%1:~1!"
  goto :normnum
)
exit /b 0

:bad_input
if defined PAUSE_AT_END pause
exit /b 2

:help
echo cat's nmap %VERSION%
echo.
echo usage: %~nx0 [-h TARGET] [-p PORTS] [-t MS] [-c N] [-a] [--keep]
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
echo example: %~nx0 -h 127.0.0.1 -p 22,80,8000-8010 -a
if defined PAUSE_AT_END pause
exit /b 0
