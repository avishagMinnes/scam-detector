# Connect the Telegram bot to its Cloud Run service. Run once, in your own terminal:
#   powershell -File deploy\set_webhook.ps1
#
# Asks for the bot token from @BotFather (typed hidden, used once, never saved or shown),
# reads the webhook secret from Google Secret Manager with the personal
# "scam-detector" gcloud configuration, and calls Telegram's setWebhook.
#
# Uses curl.exe (built into Windows): Windows PowerShell 5's own web commands failed to
# connect to Telegram on this machine. The token reaches curl through a temporary
# config file that is deleted right after (never on the command line, so it doesn't
# appear in the process list).

$ErrorActionPreference = "Stop"
$Gcloud = "$env:LOCALAPPDATA\Google\google-cloud-sdk\bin\gcloud.cmd"
$Config = "--configuration=scam-detector"

$url = (cmd /c "`"$Gcloud`" run services describe scam-detector-bot --region=us-central1 --format=value(status.url) $Config 2>nul").Trim()
if (-not $url) { throw "Bot service not found. Run infra\tf.ps1 apply first." }
$secret = (cmd /c "`"$Gcloud`" secrets versions access latest --secret=telegram-webhook-secret $Config 2>nul").Trim()
if (-not $secret) { throw "Could not read the webhook secret." }

$secure = Read-Host "Bot token from @BotFather (hidden)" -AsSecureString
$token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
$bodyFile = [IO.Path]::GetTempFileName()
try {
    if ($token -notmatch '^\d+:[A-Za-z0-9_-]+$') { throw "That doesn't look like a bot token (digits:letters)." }
    $body = @{
        url                  = "$url/telegram/webhook"
        secret_token         = $secret
        allowed_updates      = @("message", "callback_query")
        drop_pending_updates = $true
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($bodyFile, $body, (New-Object Text.UTF8Encoding $false))

    function Call-Telegram($method, $withBody) {
        # curl reads the request (with the token) from a temp config file that exists
        # for under a second: piping it from Windows PowerShell 5 garbles the text
        $cfg = "url = `"https://api.telegram.org/bot$token/$method`"`n"
        if ($withBody) {
            $cfg += "header = `"Content-Type: application/json`"`ndata-binary = `"@$($bodyFile -replace '\\', '/')`"`n"
        }
        $cfgFile = [IO.Path]::GetTempFileName()
        try {
            [IO.File]::WriteAllText($cfgFile, $cfg, (New-Object Text.UTF8Encoding $false))
            $out = curl.exe -s -m 30 -K $cfgFile
        } finally {
            Remove-Item $cfgFile -ErrorAction SilentlyContinue
        }
        if (-not $out) { throw "No answer from Telegram ($method)." }
        return ($out | ConvertFrom-Json)
    }

    $res = Call-Telegram "setWebhook" $true
    if ($res.ok) { Write-Host "Webhook set: $url/telegram/webhook" -ForegroundColor Green }
    else { Write-Host "Telegram said: $($res.description)" -ForegroundColor Red }
    $me = Call-Telegram "getMe" $false
    if ($me.ok) { Write-Host "Bot: @$($me.result.username)" }
} finally {
    $token = $null
    $secure.Dispose()
    Remove-Item $bodyFile -ErrorAction SilentlyContinue   # held the webhook secret
}
