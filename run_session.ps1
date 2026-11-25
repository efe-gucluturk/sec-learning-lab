$mtx = New-Object System.Threading.Mutex($false, "Global\SecLabQueue"); try { [void]$mtx.WaitOne() } catch [System.Threading.AbandonedMutexException] {}
# run_session.ps1
# Runs the next pending exercise from curriculum.json with Claude Code,
# commits and pushes the result, and removes the scheduled tasks after exercise 21.

$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

$LogFile = Join-Path $PSScriptRoot "session_runner.log"
$CurriculumPath = Join-Path $PSScriptRoot "curriculum.json"

function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

function Stop-LabSchedule {
    "SecLab-Sabah", "SecLab-Ogle", "SecLab-Aksam" | ForEach-Object {
        Unregister-ScheduledTask -TaskName $_ -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-Log "All 21 sessions complete. Scheduled tasks automatically removed."
}

function Get-Curriculum {
    return @(Get-Content -Path $CurriculumPath -Raw | ConvertFrom-Json)
}

# --- 1. Pick the next pending exercise ---
$items = Get-Curriculum
$next = $items | Where-Object { $_.status -eq "pending" } | Select-Object -First 1

if (-not $next) {
    Stop-LabSchedule
    exit 0
}

$folder = $next.folder
$slotLabel = "day{0:D2}-{1}" -f $next.day, $next.slot
Write-Log "Starting exercise $($next.id)/21: $folder ($($next.title))"

# --- 2. Ask Claude to do the exercise ---
$prompt = @"
You are helping with a beginner-friendly Python security practice repository.
Today's exercise (id $($next.id) of 21):
  Folder:  $folder
  Title:   $($next.title)
  Summary: $($next.summary)

Do the following, in order:
1. Create $folder/solution.py: clean, well-commented beginner Python, 60-120 lines, standard library preferred,
   with a small command-line interface. Create $folder/test_solution.py with pytest tests for it.
   Tests must not need real network access (use local data, sockets on localhost, or sample strings).
2. Run 'ruff check $folder' and 'pytest $folder'. Fix any errors until both pass.
3. In curriculum.json set "status" to "done" for the item with id $($next.id).
   In README.md change that exercise's row (the one containing `$folder`) from Pending to Completed.
Do not touch other exercises. Do not run git commands; the runner script handles commits.
"@

& claude -p $prompt --allowedTools "Bash,Read,Write,Edit"
Write-Log "Claude exited with code $LASTEXITCODE"

# --- 3. Commit and push ---
git add -A
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
    git commit -m "feat($slotLabel): $($next.title)"
    if ($LASTEXITCODE -eq 0) {
        git push origin main
        if ($LASTEXITCODE -eq 0) { Write-Log "Committed and pushed: $slotLabel" }
        else { Write-Log "Commit succeeded but push failed (exit $LASTEXITCODE)" }
    }
    else {
        Write-Log "git commit failed (exit $LASTEXITCODE)"
    }
}
else {
    Write-Log "No changes to commit for $folder"
}

# --- 4. Shut down the schedule after the last exercise ---
$remaining = @(Get-Curriculum | Where-Object { $_.status -eq "pending" })
if ($remaining.Count -eq 0) {
    Stop-LabSchedule
}

