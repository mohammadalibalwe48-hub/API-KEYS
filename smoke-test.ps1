# End-to-end smoke test against the live Supabase REST/Auth API.
#   ./smoke-test.ps1                          -> signs up a brand-new throwaway account
#   ./smoke-test.ps1 -Email you@example.com   -> logs in with an existing account
param([string]$Email = '')

$ErrorActionPreference = 'Continue'
$url = 'https://hszumyzujgnjvetvnben.supabase.co'
$key = 'sb_publishable_ZykahRBEZrE3FoQ0BdvaDw_oHRoamki'
$anon = @{ apikey = $key; Authorization = "Bearer $key"; 'Content-Type' = 'application/json' }

$email = if ($Email) { $Email } else { "kvsmoke$([guid]::NewGuid().ToString('N').Substring(0,10))@gmail.com" }
$password = 'Test-Password-123!'
Write-Host "TEST_EMAIL=$email"
if ($Email) { Write-Host 'MODE=existing-account' } else { Write-Host 'MODE=new-signup' }

function Show($label, $value) { Write-Host "$label=$(($value | ConvertTo-Json -Compress -Depth 5))" }

# Read the raw error body even when PowerShell cannot auto-parse it.
function Read-ErrorBody($err) {
    if ($err.ErrorDetails.Message) { return $err.ErrorDetails.Message }
    try {
        $stream = $err.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        return $reader.ReadToEnd()
    } catch { return '<unreadable>' }
}

# 1. Sign up ---------------------------------------------------------------
if ($Email) { Write-Host 'SIGNUP=skipped' } else {
try {
    $signup = Invoke-RestMethod -Method Post -Uri "$url/auth/v1/signup" -Headers $anon -Body (@{
        email = $email; password = $password
    } | ConvertTo-Json)
    $token = $signup.access_token
    Show 'SIGNUP' (@{ has_session = [bool]$token; needs_confirm = -not [bool]$token })
} catch {
    Show 'SIGNUP_ERROR' (@{ status = $_.Exception.Response.StatusCode.value__; body = (Read-ErrorBody $_) })
}
}

# 2. Sign in if no session yet --------------------------------------------
if (-not $token) {
    try {
        $login = Invoke-RestMethod -Method Post -Uri "$url/auth/v1/token?grant_type=password" -Headers $anon -Body (@{
            email = $email; password = $password
        } | ConvertTo-Json)
        $token = $login.access_token
        Show 'LOGIN' (@{ has_token = [bool]$token })
    } catch {
        Show 'LOGIN_ERROR' (@{ status = $_.Exception.Response.StatusCode.value__; body = (Read-ErrorBody $_) })
    }
}

if (-not $token) { Write-Host 'RESULT=NEEDS_EMAIL_CONFIRM'; exit 2 }
$auth = @{ apikey = $key; Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

# 3. Create an encrypted key via RPC --------------------------------------
try {
    $created = Invoke-RestMethod -Method Post -Uri "$url/rest/v1/rpc/create_api_key" -Headers $auth -Body (@{
        p_provider = 'TokenHarbor'; p_api_key = 'sk-smoke-1234567890ABCD'
        p_label = 'Smoke test'; p_description = 'created by smoke test'
        p_api_base_url = 'https://api.tokenharbor.example'
    } | ConvertTo-Json)
    Show 'CREATE' (@{ id = $created.id; provider = $created.provider; last4 = $created.key_last4; returned_fields = ($created.PSObject.Properties.Name -join ',') })
} catch {
    Show 'CREATE_ERROR' (@{ status = $_.Exception.Response.StatusCode.value__; body = $_.ErrorDetails.Message }); exit 1
}

# 4. List rows (RLS-scoped) ------------------------------------------------
try {
    $rows = Invoke-RestMethod -Method Get -Uri "$url/rest/v1/api_keys?select=id,provider,label,key_last4" -Headers $auth
    Show 'LIST' (@{ count = @($rows).Count; has_ciphertext = [bool]($rows[0].PSObject.Properties.Name -contains 'key_ciphertext') })
} catch {
    Show 'LIST_ERROR' (@{ status = $_.Exception.Response.StatusCode.value__; body = $_.ErrorDetails.Message })
}

# 5. Reveal (decrypt) via RPC ---------------------------------------------
try {
    $plain = Invoke-RestMethod -Method Post -Uri "$url/rest/v1/rpc/get_api_key_secret" -Headers $auth -Body (@{ p_id = $created.id } | ConvertTo-Json)
    Show 'REVEAL' (@{ exact_match = ($plain -eq 'sk-smoke-1234567890ABCD') })
} catch {
    Show 'REVEAL_ERROR' (@{ status = $_.Exception.Response.StatusCode.value__; body = $_.ErrorDetails.Message })
}

# 6. Update metadata, keep key --------------------------------------------
try {
    $updated = Invoke-RestMethod -Method Post -Uri "$url/rest/v1/rpc/update_api_key" -Headers $auth -Body (@{
        p_id = $created.id; p_provider = 'SeekAI'; p_label = 'Renamed'
        p_description = $null; p_api_base_url = $null; p_api_key = $null
    } | ConvertTo-Json)
    $plain2 = Invoke-RestMethod -Method Post -Uri "$url/rest/v1/rpc/get_api_key_secret" -Headers $auth -Body (@{ p_id = $created.id } | ConvertTo-Json)
    Show 'UPDATE' (@{ provider = $updated.provider; label = $updated.label; key_unchanged = ($plain2 -eq 'sk-smoke-1234567890ABCD') })
} catch {
    Show 'UPDATE_ERROR' (@{ status = $_.Exception.Response.StatusCode.value__; body = $_.ErrorDetails.Message })
}

# 7. Delete ---------------------------------------------------------------
try {
    Invoke-RestMethod -Method Post -Uri "$url/rest/v1/rpc/delete_api_key" -Headers $auth -Body (@{ p_id = $created.id } | ConvertTo-Json) | Out-Null
    $after = Invoke-RestMethod -Method Get -Uri "$url/rest/v1/api_keys?select=id" -Headers $auth
    Show 'DELETE' (@{ remaining = @($after).Count })
} catch {
    Show 'DELETE_ERROR' (@{ status = $_.Exception.Response.StatusCode.value__; body = $_.ErrorDetails.Message })
}

Write-Host 'RESULT=DONE'