[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
try {
    $r = Invoke-WebRequest -Uri 'https://bitsctf-2026.hvijay.dev/' -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
    Write-Output "Status: $($r.StatusCode)"
    Write-Output "Body: $($r.Content.Substring(0, [Math]::Min(2000, $r.Content.Length)))"
} catch [System.Net.WebException] {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Output "HTTP Status: $status"
    Write-Output "Error: $($_.Exception.Message)"
    # Try to read error body
    try {
        $errStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errStream)
        Write-Output "Error Body: $($reader.ReadToEnd())"
    } catch {}
}
