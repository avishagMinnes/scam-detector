# Connect the Telegram bot to its Cloud Run service. Run once, in your own terminal:
#   powershell -File deploy\set_webhook.ps1
#
# Asks for the bot token from @BotFather (typed hidden, used once, never saved or shown),
# reads the webhook secret from Google Secret Manager with the personal
# "scam-detector" gcloud configuration, and calls Telegram's setWebhook.

$ErrorActionPreference = "Stop"
$Gcloud = "$env:LOCALAPPDATA\Google\google-cloud-sdk\bin\gcloud.cmd"
$Config = "--configuration=scam-detector"

$url = (cmd /c "`"$Gcloud`" run services describe scam-detector-bot --region=us-central1 --format=value(status.url) $Config 2>nul").Trim()
if (-not $url) { throw "Bot service not found. Run infra\tf.ps1 apply first." }
$secret = (cmd /c "`"$Gcloud`" secrets versions access latest --secret=telegram-webhook-secret $Config 2>nul").Trim()
if (-not $secret) { throw "Could not read the webhook secret." }

$secure = Read-Host "Bot token from @BotFather (hidden)" -AsSecureString
$token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
try {
    $body = @{
        url                  = "$url/telegram/webhook"
        secret_token         = $secret
        allowed_updates      = @("message", "callback_query")
        drop_pending_updates = $true
    } | ConvertTo-Json
    $res = Invoke-RestMethod -Method Post -Uri "https://api.telegram.org/bot$token/setWebhook" `
        -ContentType "application/json" -Body $body
    if ($res.ok) { Write-Host "Webhook set: $url/telegram/webhook" -ForegroundColor Green }
    else { Write-Host "Telegram said: $($res.description)" -ForegroundColor Red }
    $me = Invoke-RestMethod -Uri "https://api.telegram.org/bot$token/getMe"
    Write-Host "Bot: @$($me.result.username)"
} finally {
    $token = $null; $secure.Dispose()
}
