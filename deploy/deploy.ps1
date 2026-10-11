# Build the image, push it to Artifact Registry and deploy it to Cloud Run (private).
#
# Uses the separate gcloud configuration "scam-detector" (personal account), never the
# default one. Run from the project folder:   powershell -File deploy\deploy.ps1
#
# One-time setup already done (2026-10-11): project scam-detector-511311 on the free
# trial with a $5 budget alert; Cloud Run + Artifact Registry enabled; repository
# "scam-detector" in us-central1 with cleanup-policy.json (keep 2 newest images).

$ErrorActionPreference = "Stop"
$Project = "scam-detector-511311"
$Region = "us-central1"
$Image = "$Region-docker.pkg.dev/$Project/scam-detector/app"
$Gcloud = "$env:LOCALAPPDATA\Google\google-cloud-sdk\bin\gcloud.cmd"
$Config = "--configuration=scam-detector"

$Tag = (git rev-parse --short HEAD).Trim()
if (git status --porcelain --untracked-files=no) { $Tag = "$Tag-dirty" }

Write-Host "== build $Image`:$Tag"
docker build -t "$Image`:$Tag" .
if ($LASTEXITCODE) { throw "build failed" }

Write-Host "== push"
# Short-lived token from the personal account; cmd passes it through unchanged
cmd /c "`"$Gcloud`" auth print-access-token $Config 2>nul | docker login -u oauth2accesstoken --password-stdin https://$Region-docker.pkg.dev"
if ($LASTEXITCODE) { throw "docker login failed" }
docker push "$Image`:$Tag"
if ($LASTEXITCODE) { throw "push failed" }

Write-Host "== deploy"
# Private (no anonymous access); scales to zero when idle; never more than 1 copy
& $Gcloud run deploy scam-detector "--image=$Image`:$Tag" "--region=$Region" `
    --no-allow-unauthenticated --min-instances=0 --max-instances=1 `
    --memory=2Gi --cpu=1 --cpu-boost --concurrency=4 --timeout=60 --port=8080 $Config
if ($LASTEXITCODE) { throw "deploy failed" }
