# Exercises the deployed test-api-key Edge Function end to end.
#   ./test-function.ps1 -Email you@example.com
param([Parameter(Mandatory = $true)][string]$Email)

$ErrorActionPreference = 'Continue'
$url = 'https://hszumyzujgnjvetvnben.supabase.co'
$key = 'sb_publishable_ZykahRBEZrE3FoQ0BdvaDw_oHRoamki'
$anon = @{ apikey = $key; Authorization = "Bearer $key"; 'Content-Type' = 'application/json' }

# 1. Log in to get a real user JWT ----------------------------------------
$login = Invoke-RestMethod -Method Post -Uri "$url/auth/v1/token?grant_type=password" `
    -Headers $anon -Body (@{ email = $Email; password = 'Test-Password-123!' } | ConvertTo-Json)
$token = $login.access_token
$auth = @{ apikey = $key; Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
Write-Host "LOGIN=ok user=$($login.user.id)"

function New-Key($provider, $baseUrl) {
    Invoke-RestMethod -Method Post -Uri "$url/rest/v1/rpc/create_api_key" -Headers $auth -Body (@{
        p_provider     = $provider
        p_api_key      = 'sk-not-a-real-key-000000000'
        p_label        = 'function test'
        p_description  = $null
        p_api_base_url = $baseUrl
    } | ConvertTo-Json)
}

function Invoke-Probe($id) {
    $body = @{ key_id = $id; path = '/models' } | ConvertTo-Json
    try {
        $res = Invoke-RestMethod -Method Post -Uri "$url/functions/v1/test-api-key" `
            -Headers $auth -Body $body
        return @{ http = 200; payload = $res }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $raw = $null
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $raw = $reader.ReadToEnd()
        } catch { }
        # Non-2xx bodies are still JSON from the function; parse so the
        # error/hint fields are readable.
        $parsed = $raw
        try { $parsed = $raw | ConvertFrom-Json } catch { }
        return @{ http = $code; payload = $parsed }
    }
}

# 2. Real provider, deliberately invalid key -> should report auth failure
$k1 = New-Key 'Custom' 'https://api.openai.com/v1'
$r1 = Invoke-Probe $k1.id
Write-Host 'CASE_INVALID_KEY:'
Write-Host "  http=$($r1.http) ok=$($r1.payload.ok) status=$($r1.payload.status)"
Write-Host "  message=$($r1.payload.message)"
Write-Host "  leaked_key_in_response=$([bool](($r1.payload | ConvertTo-Json -Depth 6) -match 'sk-not-a-real-key'))"

# 3. SSRF guard: private address must be refused
$k2 = New-Key 'Custom' 'https://127.0.0.1/v1'
$r2 = Invoke-Probe $k2.id
Write-Host 'CASE_SSRF_BLOCK:'
Write-Host "  http=$($r2.http) ok=$($r2.payload.ok)"
Write-Host "  message=$($r2.payload.error)"

# 4. Missing base URL for Custom -> clear, actionable error
$k3 = New-Key 'Custom' $null
$r3 = Invoke-Probe $k3.id
Write-Host 'CASE_NO_BASE_URL:'
Write-Host "  http=$($r3.http) ok=$($r3.payload.ok)"
Write-Host "  message=$($r3.payload.error)"
Write-Host "  hint=$($r3.payload.hint)"

# 5. Cross-user access: another user's id must not be readable
$k4 = New-Key 'Custom' 'https://api.openai.com/v1'
$bogus = [guid]::NewGuid().ToString()
$r5 = Invoke-Probe $bogus
Write-Host 'CASE_UNKNOWN_KEY:'
Write-Host "  http=$($r5.http) ok=$($r5.payload.ok) error=$($r5.payload.error)"

# 6. Cleanup: remove the rows created by this test
foreach ($k in @($k1, $k2, $k3, $k4)) {
    try {
        Invoke-RestMethod -Method Post -Uri "$url/rest/v1/rpc/delete_api_key" -Headers $auth `
            -Body (@{ p_id = $k.id } | ConvertTo-Json) | Out-Null
    } catch { }
}
$left = Invoke-RestMethod -Method Get -Uri "$url/rest/v1/api_keys?select=id" -Headers $auth
Write-Host "CLEANUP remaining_keys=$(@($left).Count)"
Write-Host 'RESULT=DONE'