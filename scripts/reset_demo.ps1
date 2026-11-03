# reset_demo.ps1 - get the demo back to a known-good state before a viva.
# Run from the project folder:   .\scripts\reset_demo.ps1
# It recreates the rbac-test cluster if needed and reloads the vulnerable RBAC.

Write-Host "Resetting the RBAC demo to a known-good state..." -ForegroundColor Cyan
python -m rbacgraph.demo reset
Write-Host "`nDone. Refresh the dashboard and scan kind-rbac-test." -ForegroundColor Green
