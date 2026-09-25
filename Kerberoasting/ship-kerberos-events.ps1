$WorkspaceId = "YOUR-WORKSPACE-ID"
$SharedKey   = "YOUR-PRIMARY-KEY"

$StateFileKerb  = "C:\Scripts\lastRecordId_4769.txt"
$StateFileSpray = "C:\Scripts\lastRecordId_4625.txt"

function Build-Signature($customerId,$sharedKey,$date,$contentLength,$method,$contentType,$resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = "$method`n$contentLength`n$contentType`n$xHeaders`n$resource"
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $keyBytes
    $hash = [Convert]::ToBase64String($hmac.ComputeHash($bytesToHash))
    return "SharedKey ${customerId}:${hash}"
}

function Send-ToLogAnalytics($records, $logType) {
    if (-not $records) { return }
    $jsonBody = $records | ConvertTo-Json -Depth 5
    if ($records.Count -eq 1) { $jsonBody = "[$jsonBody]" }
    $body = [Text.Encoding]::UTF8.GetBytes($jsonBody)
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $resource = "/api/logs"
    $contentType = "application/json"
    $signature = Build-Signature $WorkspaceId $SharedKey $rfc1123date $body.Length "POST" $contentType $resource
    $uri = "https://$WorkspaceId.ods.opinsights.azure.com$resource`?api-version=2016-04-01"
    $headers = @{ "Authorization" = $signature; "Log-Type" = $logType; "x-ms-date" = $rfc1123date }
    $response = Invoke-WebRequest -Uri $uri -Method Post -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    Write-Output "$logType -> Status: $($response.StatusCode)"
}

# ---- Kerberoasting: EventID 4769 ----
if (Test-Path $StateFileKerb) { $lastKerbId = [int64](Get-Content $StateFileKerb) } else { $lastKerbId = 0 }
$kerbEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -ErrorAction SilentlyContinue |
    Where-Object { $_.RecordId -gt $lastKerbId } | Sort-Object RecordId
if ($kerbEvents) {
    $kerbRecords = foreach ($e in $kerbEvents) {
        $xml = [xml]$e.ToXml()
        $d = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeGenerated         = $e.TimeCreated.ToUniversalTime().ToString("o")
            Computer               = $e.MachineName
            EventRecordId          = $e.RecordId
            TargetUserName         = ($d | Where-Object Name -eq 'TargetUserName').'#text'
            ServiceName             = ($d | Where-Object Name -eq 'ServiceName').'#text'
            TicketEncryptionType   = ($d | Where-Object Name -eq 'TicketEncryptionType').'#text'
            IpAddress               = ($d | Where-Object Name -eq 'IpAddress').'#text'
        }
    }
    Send-ToLogAnalytics $kerbRecords "KerberoastDetection"
    ($kerbEvents | Select-Object -Last 1).RecordId | Out-File $StateFileKerb
}

# ---- Password Spraying: EventID 4625 ----
if (Test-Path $StateFileSpray) { $lastSprayId = [int64](Get-Content $StateFileSpray) } else { $lastSprayId = 0 }
$sprayEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue |
    Where-Object { $_.RecordId -gt $lastSprayId } | Sort-Object RecordId
if ($sprayEvents) {
    $sprayRecords = foreach ($e in $sprayEvents) {
        $xml = [xml]$e.ToXml()
        $d = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeGenerated     = $e.TimeCreated.ToUniversalTime().ToString("o")
            Computer           = $e.MachineName
            EventRecordId      = $e.RecordId
            TargetUserName     = ($d | Where-Object Name -eq 'TargetUserName').'#text'
            IpAddress           = ($d | Where-Object Name -eq 'IpAddress').'#text'
            LogonType           = ($d | Where-Object Name -eq 'LogonType').'#text'
            FailureReason       = ($d | Where-Object Name -eq 'FailureReason').'#text'
            SubStatus           = ($d | Where-Object Name -eq 'SubStatus').'#text'
        }
    }
    Send-ToLogAnalytics $sprayRecords "AuthFailureDetection"
    ($sprayEvents | Select-Object -Last 1).RecordId | Out-File $StateFileSpray
}
