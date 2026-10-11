# Run Terraform for infra\ with a short-lived token from the personal "scam-detector"
# gcloud configuration. It never uses or changes the machine's default Google
# credentials (which belong to a different account).
#
#   powershell -File infra\tf.ps1 init
#   powershell -File infra\tf.ps1 plan
#   powershell -File infra\tf.ps1 apply

$ErrorActionPreference = "Stop"
$Gcloud = "$env:LOCALAPPDATA\Google\google-cloud-sdk\bin\gcloud.cmd"
$token = (cmd /c "`"$Gcloud`" auth print-access-token --configuration=scam-detector 2>nul").Trim()
if (-not $token) { throw "No token: run  gcloud auth login --configuration=scam-detector" }

$env:GOOGLE_OAUTH_ACCESS_TOKEN = $token   # only for this process and its children
try {
    terraform "-chdir=$PSScriptRoot" @args
    exit $LASTEXITCODE
} finally {
    Remove-Item Env:GOOGLE_OAUTH_ACCESS_TOKEN -ErrorAction SilentlyContinue
}
