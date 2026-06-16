$choices = @{}
$script:reportCache = @{}          # Кэш для глубокого анализа
$script:onlineHostsList = @()      # Общий список онлайн-хостов

# ---- Вспомогательные функции для IP ----
function Convert-IPToUInt32 {
    param([string]$ipAddress)
    $bytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes()
    [System.Array]::Reverse($bytes)
    return [System.BitConverter]::ToUInt32($bytes, 0)
}

function Convert-UInt32ToIP {
    param([uint32]$intAddress)
    $bytes = [System.BitConverter]::GetBytes($intAddress)
    [System.Array]::Reverse($bytes)
    return [System.Net.IPAddress]::new($bytes).ToString()
}

function Get-IPRange {
    param([string]$network, [int]$prefix)
    if ($prefix -lt 0 -or $prefix -gt 32) { throw "Prefix must be 0-32" }
    $networkUint = Convert-IPToUInt32 $network
    $maskUint = ([uint32]::MaxValue) -shl (32 - $prefix)
    $networkUint = $networkUint -band $maskUint
    $broadcastUint = $networkUint -bor ((-bnot $maskUint) -as [uint32])
    switch ($prefix) {
        31 { $firstHost = $networkUint; $lastHost = $broadcastUint }
        32 { $firstHost = $networkUint; $lastHost = $networkUint }
        default { $firstHost = $networkUint + 1; $lastHost = $broadcastUint - 1 }
    }
    return @{
        FirstHost = $firstHost
        LastHost  = $lastHost
        Count     = if ($lastHost -ge $firstHost) { $lastHost - $firstHost + 1 } else { 0 }
        Network   = Convert-UInt32ToIP $networkUint
        Broadcast = Convert-UInt32ToIP $broadcastUint
    }
}

# ---- Анимация ----
function Show-Animation {
    param([string]$Message, [int]$Delay = 30)
    foreach ($ch in $Message.ToCharArray()) {
        Write-Host $ch -NoNewline -ForegroundColor Cyan
        Start-Sleep -Milliseconds $Delay
    }
    Write-Host ""
}

# ---- Сканирование одной подсети ----
function Scan-Subnet {
    param(
        [string]$SubnetCIDR,
        [int]$MaxThreads
    )

    $subnetInput = $SubnetCIDR.Trim()
    if (-not ($subnetInput -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/([0-9]|[1-2][0-9]|3[0-2])$')) {
        Write-Host "[-] Invalid CIDR: $subnetInput" -ForegroundColor Red
        return @()
    }
    $a=[int]$Matches[1];$b=[int]$Matches[2];$c=[int]$Matches[3];$d=[int]$Matches[4];$prefix=[int]$Matches[5]
    if (($a,$b,$c,$d | Where-Object {$_ -gt 255})) {
        Write-Host "[-] Invalid IP octets in $subnetInput" -ForegroundColor Red
        return @()
    }
    $baseIP = "$a.$b.$c.$d"
    $range = Get-IPRange -network $baseIP -prefix $prefix
    $correctedNetwork = $range.Network
    if ($correctedNetwork -ne $baseIP) {
        Write-Host "[!] Notice: Using network address $correctedNetwork/$prefix for $subnetInput" -ForegroundColor Yellow
    }

    $totalHosts = $range.Count
    if ($totalHosts -eq 0) {
        Write-Host "[-] No hosts in $subnetInput" -ForegroundColor Red
        return @()
    }

    Write-Host "[*] Scanning $correctedNetwork/$prefix ($totalHosts hosts) with $MaxThreads threads..." -ForegroundColor Yellow
    Write-Host "---------------------------------------------------"

    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $RunspacePool.Open()

    $onlineCount = 0
    $completed = 0
    $startTime = Get-Date
    $onlineList = New-Object System.Collections.Generic.List[PSCustomObject]

    $ScriptBlock = {
        param($ip)
        $ping = New-Object System.Net.NetworkInformation.Ping
        $status = "OFFLINE"
        $ptr = "No PTR record"
        try {
            $reply = $ping.Send($ip, 30)
            if ($reply.Status -eq 'Success') {
                $status = "ONLINE"
                try { $ptr = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}
            }
        } catch {}
        return "$ip|$status|$ptr"
    }

    $ipQueue = New-Object System.Collections.Generic.Queue[string]
    for ($addr = $range.FirstHost; $addr -le $range.LastHost; $addr++) { $ipQueue.Enqueue((Convert-UInt32ToIP $addr)) }

    $activeJobs = New-Object System.Collections.Generic.List[PSCustomObject]
    function Start-PingJob {
        if ($ipQueue.Count -eq 0) { return $false }
        $targetIp = $ipQueue.Dequeue()
        $ps = [powershell]::Create().AddScript($ScriptBlock).AddArgument($targetIp)
        $ps.RunspacePool = $RunspacePool
        $job = [PSCustomObject]@{ Pipe = $ps; Result = $ps.BeginInvoke(); IP = $targetIp }
        $activeJobs.Add($job)
        return $true
    }

    for ($i=0; $i -lt $MaxThreads; $i++) { [void](Start-PingJob) }

    Write-Host "[*] Live results:" -ForegroundColor Yellow
    Write-Host "---------------------------------------------------"
    Write-Host ""

    $originalCursorTop = [Console]::CursorTop
    $progressLineTop = $originalCursorTop + 1

    while ($activeJobs.Count -gt 0 -or $ipQueue.Count -gt 0) {
        $finished = @()
        foreach ($job in $activeJobs) {
            if ($job.Result.IsCompleted) {
                $rawData = $job.Pipe.EndInvoke($job.Result)
                $job.Pipe.Dispose()
                if ($rawData) {
                    $parts = $rawData -split '\|'
                    $ip = $parts[0]; $status = $parts[1]; $ptr = $parts[2]
                    if ($status -eq "ONLINE") {
                        Write-Host "[+] ONLINE: $ip [$ptr]" -ForegroundColor Green
                        $onlineList.Add([PSCustomObject]@{ IP = $ip; PTR = $ptr })
                        $onlineCount++
                    } else {
                        Write-Host "[-] OFFLINE: $ip" -ForegroundColor DarkGray
                    }
                }
                $finished += $job
                $completed++
            }
        }
        foreach ($job in $finished) { [void]$activeJobs.Remove($job) }

        while ($activeJobs.Count -lt $MaxThreads -and $ipQueue.Count -gt 0) { [void](Start-PingJob) }

        $elapsed = (Get-Date) - $startTime
        $percent = if ($totalHosts -gt 0) { [math]::Round(($completed / $totalHosts)*100,1) } else { 0 }
        $rate = if ($elapsed.TotalSeconds -gt 0) { [math]::Round($completed / $elapsed.TotalSeconds,1) } else { 0 }
        $remaining = if ($rate -gt 0) { ($totalHosts - $completed) / $rate } else { 0 }
        $timeLeft = if ($remaining -gt 0) { [TimeSpan]::FromSeconds($remaining).ToString("hh\:mm\:ss") } else { "calculating" }
        $progressMsg = "Progress: $percent% ($completed / $totalHosts) | Online: $onlineCount | Speed: $rate hosts/s | ETA: $timeLeft | Active threads: $($activeJobs.Count)"
        $curTop = [Console]::CursorTop
        [Console]::SetCursorPosition(0, $progressLineTop)
        Write-Host $progressMsg -ForegroundColor Cyan -NoNewline
        $blank = " " * ($Host.UI.RawUI.BufferSize.Width - $progressMsg.Length)
        Write-Host $blank -NoNewline
        [Console]::SetCursorPosition(0, $curTop)
        Start-Sleep -Milliseconds 100
    }

    $RunspacePool.Close(); $RunspacePool.Dispose()
    [Console]::SetCursorPosition(0, $progressLineTop)
    Write-Host (" " * $Host.UI.RawUI.BufferSize.Width) -NoNewline
    Write-Host "`n---------------------------------------------------"
    Write-Host "[+] Subnet scan completed. Online hosts: $onlineCount" -ForegroundColor Green
    Write-Host ""

    return $onlineList
}

# ---- Главное меню ----
function Show-MainMenu {
    Clear-Host
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "     ULTRA-SPEED RUNSPACE DISCOVERY SCANNER        " -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Example: 10.5.1.0/24 or 192.168.0.0/16 or 77.50.201.128/25"
    Write-Host "You can enter several subnets separated by commas:"
    Write-Host "  10.5.1.0/24, 192.168.0.0/16, 77.50.201.0/24"
    Write-Host ""

    $rawInput = Read-Host "Enter subnet(s) (CIDR)"
    $rawInput = $rawInput -replace '\s+', '' -replace '^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$', ''
    if ([string]::IsNullOrWhiteSpace($rawInput)) { 
        Write-Host "`n[-] Empty input." -ForegroundColor Red; Start-Sleep 1; return 
    }

    # Разбиваем на массив CIDR
    $cidrList = $rawInput -split ',' | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() }
    if ($cidrList.Count -eq 0) {
        Write-Host "`n[-] No valid CIDR entered." -ForegroundColor Red; Pause; return
    }

    # Запрос количества потоков
    $defaultThreads = 200
    Write-Host "`n[?] Concurrent threads (default $defaultThreads, max 2000):"
    $threadsInput = Read-Host
    $maxThreads = if ([int]::TryParse($threadsInput, [ref]$null)) { [math]::Min([int]$threadsInput, 2000) } else { $defaultThreads }
    Write-Host "[*] Using $maxThreads threads" -ForegroundColor Yellow

    # Предупреждение для больших объёмов
    $totalEstimated = 0
    foreach ($cidr in $cidrList) {
        if ($cidr -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/([0-9]|[1-2][0-9]|3[0-2])$') {
            $network = $Matches[1]
            $prefix = [int]$Matches[2]
            $range = Get-IPRange -network $network -prefix $prefix -ErrorAction SilentlyContinue
            if ($range) { $totalEstimated += $range.Count }
        }
    }
    if ($totalEstimated -gt 50000) {
        Write-Host "`n[!] Total hosts across all subnets: ~$totalEstimated. Scanning may take a while." -ForegroundColor Yellow
        $confirm = Read-Host "Continue? (y/n)"
        if ($confirm -ne 'y') { return }
    }

    # Сканируем каждую подсеть и объединяем результаты
    $allOnline = New-Object System.Collections.Generic.List[PSCustomObject]
    $subnetIndex = 1
    foreach ($cidr in $cidrList) {
        Write-Host "`n--- Scanning subnet $subnetIndex of $($cidrList.Count): $cidr ---" -ForegroundColor Magenta
        $result = Scan-Subnet -SubnetCIDR $cidr -MaxThreads $maxThreads
        if ($result.Count -gt 0) {
            foreach ($hostObj in $result) {
                $allOnline.Add($hostObj)
            }
        }
        $subnetIndex++
    }

    if ($allOnline.Count -eq 0) {
        Write-Host "`n[-] No online hosts found in any subnet." -ForegroundColor Red
        Pause
        return
    }

    # Сохраняем глобально
    $script:onlineHostsList = $allOnline

    # Цикл показа списка хостов с очисткой экрана
    while ($true) {
        Clear-Host
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "                 ONLINE HOSTS LIST                 " -ForegroundColor Cyan
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "  Total online hosts: $($allOnline.Count)" -ForegroundColor Yellow
        Write-Host ""

        $script:choices = @{}
        $cnt = 1
        foreach ($hostInfo in ($script:onlineHostsList | Sort-Object { [version]$_.IP })) {
            Write-Host "[$cnt] ONLINE: $($hostInfo.IP) [$($hostInfo.PTR)]" -ForegroundColor Green
            $script:choices[$cnt.ToString()] = $hostInfo.IP
            $cnt++
        }

        Write-Host ""
        Write-Host "---------------------------------------------------"
        Write-Host "0] Return to Main Menu"
        Write-Host "---------------------------------------------------"

        $choice = Read-Host "Select host number"
        if ($choice -eq "0" -or [string]::IsNullOrWhiteSpace($choice)) { 
            Clear-Host
            break 
        }
        if ($script:choices.ContainsKey($choice)) {
            Show-FullReport $script:choices[$choice]
        }
    }
}

# ---- Отчёт по хосту (без изменений, кроме интеграции) ----
function Show-FullReport($ip) {
    Clear-Host
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "           COMPLETE INTELLIGENCE REPORT            " -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host " Target IP: $ip" -ForegroundColor Yellow
    Write-Host "---------------------------------------------------`n"

    # ---- 1. Basic Info & Ping ----
    Write-Host "[1] NETWORK LAYER & PING" -ForegroundColor Cyan
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply = $ping.Send($ip, 120)
        if ($reply.Status -eq 'Success') {
            Write-Host "  Ping Status:   SUCCESS ($($reply.RoundtripTime) ms)" -ForegroundColor Green
            Write-Host "  TTL Value:     $($reply.Options.Ttl)"
            if ($reply.Options.Ttl -le 64) { $os = "Linux/Unix/Android/Cisco" }
            elseif ($reply.Options.Ttl -le 128) { $os = "Windows" }
            else { $os = "Router/Network device" }
            Write-Host "  OS Guess:      $os"
        } else { Write-Host "  Ping Status:   FAILED" -ForegroundColor Red }
    } catch { Write-Host "  Ping Status:   ERROR" -ForegroundColor Red }
    $ptr = try { [System.Net.Dns]::GetHostEntry($ip).HostName } catch { "Not found" }
    Write-Host "  PTR Record:    $ptr"
    Write-Host ""

    # ---- 2. Hardware (MAC, OUI) ----
    Write-Host "[2] HARDWARE IDENTIFICATION" -ForegroundColor Cyan
    $mac = "Unknown"
    $arp = arp -a | Select-String "$ip "
    if ($arp -and $arp.Line -match '([0-9a-f]{2}-){5}[0-9a-f]{2}') { $mac = $Matches[0].ToUpper() }
    Write-Host "  MAC Address:   $mac"
    if ($mac -ne "Unknown") {
        try {
            $oui = ($mac -replace '-', '').Substring(0,6)
            $vendor = Invoke-RestMethod -Uri "https://api.macvendors.com/$oui" -TimeoutSec 2
            Write-Host "  Vendor:        $vendor"
        } catch { Write-Host "  Vendor lookup failed" }
    }
    Write-Host ""

    # ---- 3. Geolocation & ISP ----
    Write-Host "[3] GEOLOCATION & ISP" -ForegroundColor Cyan
    $ipType = if ($ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') { "Private (LAN)" } else { "Public" }
    Write-Host "  Scope:         $ipType"
    if ($ipType -eq "Public") {
        try {
            $geo = Invoke-RestMethod -Uri "https://ipinfo.io/$ip/json" -TimeoutSec 4
            Write-Host "  Country:       $($geo.country)"
            Write-Host "  City/Region:   $($geo.city), $($geo.region)"
            Write-Host "  Coordinates:   $($geo.loc)"
            Write-Host "  ISP/Org:       $($geo.org)"
        } catch { Write-Host "  Geolocation service unavailable." }
    } else {
        Write-Host "  Local network - no external geolocation."
    }
    Write-Host ""

    # ---- 4. TCP Ports Scan (common) ----
    Write-Host "[4] COMMON TCP PORTS" -ForegroundColor Cyan
    $ports = @{
        21="FTP";22="SSH";23="Telnet";25="SMTP";53="DNS";80="HTTP";110="POP3";
        111="RPC";135="RPC";139="NetBIOS";143="IMAP";443="HTTPS";445="SMB";
        993="IMAPS";995="POP3S";1433="MSSQL";3306="MySQL";3389="RDP";
        5432="PostgreSQL";5900="VNC";6379="Redis";8080="HTTP-Alt";8443="HTTPS-Alt"
    }
    $webPortsOpen = $false
    foreach ($port in ($ports.Keys | Sort-Object)) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($ip, $port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne(60, $false)
        [void]$wait
        if ($tcp.Connected) {
            Write-Host "  Port $port ($($ports[$port])) : OPEN" -ForegroundColor Green
            if ($port -eq 80 -or $port -eq 8080 -or $port -eq 443 -or $port -eq 8443) {
                $webPortsOpen = $true
                try {
                    $url = "http://${ip}:$port"
                    $req = [System.Net.WebRequest]::Create($url)
                    $req.Timeout = 300
                    $res = $req.GetResponse()
                    $server = $res.Headers["Server"]
                    if ($server) { Write-Host "      Server: $server" -ForegroundColor Gray }
                    $res.Close()
                } catch {}
            }
        } else {
            Write-Host "  Port $port ($($ports[$port])) : closed" -ForegroundColor DarkGray
        }
        $tcp.Close()
    }
    Write-Host ""

    # ---- 5. DNS Deep Dive (опционально) ----
    if ($webPortsOpen) {
        Write-Host "[5] DEEP DNS ENUMERATION (DNSDUMPSTER STYLE)" -ForegroundColor Cyan
        Write-Host "  Web ports detected (80/443/8080/8443). Do you want to perform deep DNS enumeration?" -ForegroundColor Yellow
        $performDeep = Read-Host "  Perform deep analysis? (y/n)"
        if ($performDeep -eq 'y') {
            if ($script:reportCache.ContainsKey($ip)) {
                Show-Animation "  Loading cached results..." -Delay 20
                Write-Host $script:reportCache[$ip]
            } else {
                Show-Animation "  Starting deep DNS reconnaissance..." -Delay 20
                $deepReport = Get-DeepDnsReport $ip
                $script:reportCache[$ip] = $deepReport
                Write-Host $deepReport
            }
        } else {
            Write-Host "  Skipping deep DNS enumeration." -ForegroundColor DarkGray
        }
    } else {
        Write-Host "[5] DEEP DNS ENUMERATION" -ForegroundColor Cyan
        Write-Host "  No web ports (80,443,8080,8443) open. Skipping deep analysis." -ForegroundColor DarkGray
    }

    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "0] Back to online hosts list"
    Write-Host "===================================================" -ForegroundColor Cyan
    $null = Read-Host "Select action"
}

# ---- Глубокий DNS-отчёт (без изменений) ----
function Get-DeepDnsReport($ip) {
    $output = @()
    $domain = ""
    try { 
        $domain = [System.Net.Dns]::GetHostEntry($ip).HostName
        $output += "  [+] Reverse DNS: $domain"
    } catch { 
        $output += "  [-] Reverse DNS: No PTR record"
    }

    if (-not [string]::IsNullOrWhiteSpace($domain) -and $domain -notmatch "No PTR") {
        $output += "`n  --- DNS Records for $domain ---"
        $ips = try { [System.Net.Dns]::GetHostAddresses($domain) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } } catch { $null }
        if ($ips) { $output += "    A Record(s): $($ips -join ', ')" }
        else { $output += "    A Record(s): none" }
        $ips6 = try { [System.Net.Dns]::GetHostAddresses($domain) | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' } } catch { $null }
        if ($ips6) { $output += "    AAAA Record(s): $($ips6 -join ', ')" }
        else { $output += "    AAAA Record(s): none" }

        $mx = & nslookup -type=mx $domain 2>$null | Select-String "mail exchanger"
        if ($mx) { $output += "    MX Records:"; foreach ($line in $mx) { $output += "      $line" } }
        else { $output += "    MX Records: none" }
        $txt = & nslookup -type=txt $domain 2>$null | Select-String "text"
        if ($txt) { $output += "    TXT Records:"; foreach ($line in $txt) { $output += "      $line" } }
        else { $output += "    TXT Records: none" }
        $ns = & nslookup -type=ns $domain 2>$null | Select-String "nameserver"
        if ($ns) { $output += "    NS Records:"; foreach ($line in $ns) { $output += "      $line" } }
        else { $output += "    NS Records: none" }

        $output += "`n  --- Subdomain Brute Force (top 120+) ---"
        $subs = @(
            "www","mail","ftp","blog","shop","api","admin","m","ns1","ns2","smtp","pop3","imap","vpn","remote","dev","test","cdn","static","images","video","download","webmail","cpanel","whm","autodiscover","autoconfig","forum","support","status","stats","monitor","portal","secure","ftp2","ns3","dns","dns2","mx1","mx2",
            "cloud","staging","demo","lab","internal","backup","storage","app","apps","dashboard","panel","manage","adminpanel","cp","control","owa","exchange","lync","skype","teams","sharepoint","sip","voip","sipgate","asterisk","pbx","gateway","proxy","cache","loadbalancer","lb","mysql","postgres","redis","memcache","mongodb","elastic","kibana","grafana","prometheus","jenkins","gitlab","github","bitbucket","jira","confluence","artifactory","nexus","sonar","docker","k8s","kubernetes","rancher","openshift","openshift-console","grafana","prometheus","alertmanager","thanos","loki","tempo","mimir",
            "auth","login","sso","oauth","openid","keycloak","authentik","identity","account","user","users","profile","my","members","customer","clients","partner","partners","vendor","supplier","distributor","reseller","affiliate","referral","track","tracking","analytics","metrics","mon","health","healthcheck","heartbeat","ping","statuspage","uptime","monitoring","alert","alerts","firewall","fw","vpn","openvpn","wireguard","strongswan","ipsec","ike","l2tp","pptp","sstp","ssh","ssl","tls","certs","certificates"
        )
        foreach ($sub in $subs) {
            $fqdn = "$sub.$domain"
            try {
                $addr = [System.Net.Dns]::GetHostAddresses($fqdn) | Select-Object -First 1
                if ($addr) { $output += "    [+] $fqdn -> $($addr.IPAddressToString)" }
                else { $output += "    [-] $fqdn" }
            } catch { $output += "    [-] $fqdn" }
        }

        $output += "`n  --- WHOIS (domain) ---"
        try {
            $whoisResult = & whois $domain 2>$null | Select-String -Pattern "Registrar|Creation Date|Expiry Date|Name Server|Registry Domain ID|Organization" | Select-Object -First 15
            if ($whoisResult) { foreach ($line in $whoisResult) { $output += "    $line" } }
            else { $output += "    No whois data (command not installed or domain not found)" }
        } catch { $output += "    whois command failed" }

        $output += "`n  --- SSL CERTIFICATES (HTTPS) ---"
        $sslPorts = @(443, 8443)
        foreach ($port in $sslPorts) {
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $async = $tcp.BeginConnect($ip, $port, $null, $null)
                $wait = $async.AsyncWaitHandle.WaitOne(1000, $false)
                [void]$wait
                if (-not $tcp.Connected) { throw "Timeout" }
                $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $true, { $true })
                $ssl.AuthenticateAsClient($domain)
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                $output += "    Port $port :"
                $output += "      Subject: $($cert.Subject)"
                $output += "      Issuer:  $($cert.Issuer)"
                $output += "      NotBefore: $($cert.NotBefore)"
                $output += "      NotAfter:  $($cert.NotAfter)"
                $output += "      SAN: $($cert.GetNameInfo('DnsFromAlternativeName', $false))"
                $ssl.Close(); $tcp.Close()
            } catch { $output += "    Port $port : No SSL or connection failed" }
        }

        $output += "`n  --- HTTP(S) HEADERS ---"
        $webPorts = @(80, 8080, 443, 8443)
        foreach ($port in $webPorts) {
            $proto = if ($port -eq 443 -or $port -eq 8443) { "https" } else { "http" }
            $url = "${proto}://${ip}:${port}"
            try {
                $req = [System.Net.WebRequest]::Create($url)
                $req.Timeout = 2000
                $req.Method = "HEAD"
                $res = $req.GetResponse()
                $output += "    $url :"
                $output += "      Status: $($res.StatusCode)"
                $output += "      Server: $($res.Headers['Server'])"
                $output += "      X-Powered-By: $($res.Headers['X-Powered-By'])"
                $res.Close()
            } catch {
                $output += "    $url : failed or not responding"
            }
        }
    }
    else {
        $output += "  No domain from reverse DNS. Skipping DNS enumeration."
    }
    return ($output -join "`n")
}

# ---- Запуск ----
while ($true) { Show-MainMenu }