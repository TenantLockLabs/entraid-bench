#========================================================================
# Enhanced Entra ID Security Assessment Tool
# 
# This script provides a comprehensive security assessment of Microsoft Entra ID
# environments with detailed evidence collection and HTML report generation.
#========================================================================

#region Banner and Introduction
Write-Host @"

_____       _               ___ ____    ____                  _     
| ____|_ __ | |_ _ __ __ _  |_ _|  _ \  | __ )  ___ _ __   ___| |__  
|  _| | '_ \| __| '__/ _` |  | || | | | |  _ \ / _ \ '_ \ / __| '_ \ 
| |___| | | | |_| | | (_| |  | || |_| | | |_) |  __/ | | | (__| | | |
|_____|_| |_|\__|_|  \__,_| |___|____/  |____/ \___|_| |_|\___|_| |_|

Enhanced Security Assessment Tool
"@

Write-Host "`nThis tool will perform a comprehensive security assessment of your Microsoft Entra ID environment."
Write-Host "It will generate an HTML report with detailed findings and remediation steps.`n"
#endregion

#region Module Verification and Installation
if (Get-Module -ListAvailable -Name Microsoft.Graph) {
    Write-Host "Microsoft.Graph module is already installed." -ForegroundColor Green
} else {
    Write-Host "Installing Microsoft.Graph module..." -ForegroundColor Cyan
    Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
}

# Import required modules
Import-Module Microsoft.Graph.Identity.DirectoryManagement
Import-Module Microsoft.Graph.Identity.Governance
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
#endregion

#region Authentication Function
function Connect-ToEntraID {
    [CmdletBinding()]
    param()
    
    try {
        if (Get-MgContext) {
            $context = Get-MgContext
            Write-Host "Already connected to Microsoft Graph as $($context.Account)" -ForegroundColor Green
        } else {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
            Connect-MgGraph -Scopes @(
                'UserAuthenticationMethod.Read.All',
                'User.Read.All',
                'SecurityEvents.Read.All',
                'Policy.Read.All',
                'Policy.ReadWrite.AuthenticationMethod',
                'RoleManagement.Read.All',
                'AccessReview.Read.All',
                'Directory.Read.All',
                'Group.Read.All',
                'IdentityProvider.Read.All',
                'IdentityRiskEvent.Read.All',
                'Application.Read.All'
            )
            Write-Host "Connected successfully." -ForegroundColor Green
        }
        return $true
    } catch {
        Write-Error "Error connecting to Microsoft Graph: $_"
        return $false
    }
}
#endregion

#region License Check Function
function Test-EntraP2License {
    [CmdletBinding()]
    param()
    
    try {
        # Try to call a P2-only API
        Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -Top 1 -ErrorAction Stop
        return $true
    }
    catch {
        # Check if the error is specifically about premium license requirements
        if ($_.Exception.Message -match "AadPremiumLicenseRequired" -or 
            $_.Exception.Message -match "Microsoft Entra ID P2" -or
            $_.Exception.Message -match "Entra ID Governance license") {
            Write-Host "Note: Your tenant does not have Microsoft Entra ID P2 or Governance license. Some advanced security checks will provide limited information." -ForegroundColor Yellow
            return $false
        }
        # If it's some other error, we'll consider it might be transient and not license-related
        return $true
    }
}
#endregion

#region Helper Function for HTML Report
# Load the full-featured Report Generator
if (Test-Path ".\Report-Generator.ps1") {
    . ".\Report-Generator.ps1"
} else {
    Write-Host "Warning: Report-Generator.ps1 not found. Using basic HTML generation." -ForegroundColor Yellow
    
    function ConvertTo-HTMLReport {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [PSCustomObject[]]$Results,
            
            [Parameter(Mandatory = $false)]
            [string]$ReportTitle = "Microsoft Entra ID Security Assessment Report",
            
            [Parameter(Mandatory = $false)]
            [string]$OutputPath = "EntraID_Security_Report.html"
        )
        
        # Basic HTML generation as fallback
        $html = "<html><head><title>$ReportTitle</title></head><body><h1>$ReportTitle</h1>"
        $html += "<p>Total Controls: $($Results.Count)</p>"
        
        foreach ($result in $Results) {
            $html += "<div style='margin: 10px; padding: 10px; border: 1px solid #ccc;'>"
            $html += "<h3>$($result.Control)</h3>"
            $html += "<p><strong>Result:</strong> $($result.Result)</p>"
            $html += "<p><strong>Finding:</strong> $($result.Finding)</p>"
            $html += "</div>"
        }
        
        $html += "</body></html>"
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        return $OutputPath
    }
}
#endregion

#region Main Execution
# Connect to Microsoft Graph
$connected = Connect-ToEntraID
if (-not $connected) {
    Write-Host "Failed to connect to Microsoft Graph. Exiting..." -ForegroundColor Red
    exit
}

# Check for P2 license
$hasP2License = Test-EntraP2License

# Get tenant information for the report
$tenantInfo = Get-MgOrganization | Select-Object DisplayName, Id, CreatedDateTime
Write-Host "`nPerforming security assessment for tenant: $($tenantInfo.DisplayName)" -ForegroundColor Cyan
Write-Host "Tenant ID: $($tenantInfo.Id)" -ForegroundColor Cyan

# Prepare results collection
$assessmentResults = @()

# Create temporary directory for evidence files if needed
$evidencePath = ".\Evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
if (-not (Test-Path $evidencePath)) {
    New-Item -Path $evidencePath -ItemType Directory | Out-Null
}

# Specify the path to control script files
$controlPath = "./controls"

# Get all control scripts
$controlScripts = Get-ChildItem -Path $controlPath -Filter "*.ps1" | Sort-Object Name

# Run each control check and collect results
$totalControls = $controlScripts.Count
$currentControl = 0

Write-Host "`nStarting security assessment with $totalControls controls..." -ForegroundColor Cyan

foreach ($script in $controlScripts) {
    $currentControl++
    $percentComplete = [math]::Round(($currentControl / $totalControls) * 100)
    $controlName = $script.BaseName
    
    # Show progress bar
    Write-Progress -Activity "Performing Security Assessment" -Status "Running control check: $controlName" `
                   -PercentComplete $percentComplete -CurrentOperation "Control $currentControl of $totalControls"
    
    # Execute the control check - handle graceful failure for each control
    Write-Host "[$currentControl/$totalControls] Running: $controlName..." -ForegroundColor Yellow
    
    try {
        # Check if premium license is required but not available
        $requiresP2 = $script.Name -match "PermanentActiveAssignment|UserRiskPolicy|SignInRiskPolicy"
        
        if ($requiresP2 -and -not $hasP2License) {
            # For P2-dependent controls when license isn't available, create a placeholder result
            $scriptContent = Get-Content -Path $script.FullName -Raw
            
            # Extract control title and description using regex
            if ($scriptContent -match '\$controlTitle\s*=\s*"([^"]+)"') {
                $controlTitle = $matches[1]
            } else {
                $controlTitle = "Unknown Control"
            }
            
            if ($scriptContent -match '\$controlDescription\s*=\s*"([^"]+)"') {
                $controlDescription = $matches[1]
            } else {
                $controlDescription = "No description available"
            }
            
            $result = [PSCustomObject]@{
                Control = $controlTitle
                ControlDescription = $controlDescription
                Finding = "Unable to assess - Microsoft Entra ID P2 license required."
                Result = "INFORMATION NEEDED"
                Evidence = "This control requires Microsoft Entra ID P2 or Microsoft Entra ID Governance license to assess. Consider upgrading your license to enable these advanced security features."
                RemediationSteps = "To use this feature, your organization needs Microsoft Entra ID P2 or Microsoft Entra ID Governance licenses."
                AffectedAccounts = @()
            }
        }
        else {
            # Run the control script and get the result
            $result = & "$($script.FullName)"
        }
        
        $assessmentResults += $result
        
        # Display a brief summary of the result
        $resultColor = switch ($result.Result) {
            "COMPLIANT" { "Green" }
            "PARTIALLY COMPLIANT" { "Yellow" }
            "NOT COMPLIANT" { "Red" }
            "INFORMATION NEEDED" { "Cyan" }
            "NOT APPLICABLE" { "White" }
            default { "White" }
        }
        
        Write-Host "  Result: " -NoNewline
        Write-Host $result.Result -ForegroundColor $resultColor
        Write-Host "  Finding: $($result.Finding)" -ForegroundColor Gray
        
        # Export detailed evidence to file if evidence is extensive
        if ($result.Evidence -and $result.Evidence.Length -gt 500) {
            $evidenceFileName = "$evidencePath\$($controlName)_Evidence.txt"
            $result.Evidence | Out-File -FilePath $evidenceFileName -Encoding UTF8
            Write-Host "  Detailed evidence saved to: $evidenceFileName" -ForegroundColor Cyan
        }
        
        # If there are affected accounts, save to CSV - ROBUST NULL CHECK
        if ($result.AffectedAccounts -and 
            $result.AffectedAccounts -is [System.Array] -and 
            $result.AffectedAccounts.Count -gt 0 -and
            $result.AffectedAccounts[0] -ne $null) {
            
            $accountsFileName = "$evidencePath\$($controlName)_AffectedAccounts.csv"
            try {
                # Additional validation - ensure we have actual objects
                $validAccounts = $result.AffectedAccounts | Where-Object { $_ -ne $null }
                if ($validAccounts -and $validAccounts.Count -gt 0) {
                    $validAccounts | Export-Csv -Path $accountsFileName -NoTypeInformation
                    Write-Host "  Affected accounts saved to: $accountsFileName" -ForegroundColor Cyan
                } else {
                    Write-Host "  Warning: AffectedAccounts array contains null values, skipping CSV export" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  Warning: Could not export affected accounts to CSV: $_" -ForegroundColor Yellow
            }
        }
        
    } catch {
        Write-Host "  Error running control check: $_" -ForegroundColor Red
        
        # Add error information to results
        $assessmentResults += [PSCustomObject]@{
            Control = $controlName
            ControlDescription = "Error executing control check"
            Finding = "An error occurred: $_"
            Result = "ERROR"
            Evidence = "Error details:`n$_`n`nStack Trace:`n$($_.ScriptStackTrace)"
            AffectedAccounts = @()
            RemediationSteps = "Review the error details above and ensure proper permissions and connectivity."
        }
    }
    
    Write-Host ""
}

# Complete the progress bar
Write-Progress -Activity "Performing Security Assessment" -Completed

# Generate the HTML report
Write-Host "Generating HTML report..." -ForegroundColor Cyan
$reportPath = ".\EntraID_Security_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$generatedReport = ConvertTo-HTMLReport -Results $assessmentResults -OutputPath $reportPath

# Export raw results to CSV for reference
$csvPath = ".\EntraID_Security_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$assessmentResults | Select-Object Control, Finding, Result | Export-Csv -Path $csvPath -NoTypeInformation

# Calculate compliance statistics
$totalControls = $assessmentResults.Count
$compliantControls = ($assessmentResults | Where-Object { $_.Result -eq "COMPLIANT" }).Count
$partiallyCompliantControls = ($assessmentResults | Where-Object { $_.Result -eq "PARTIALLY COMPLIANT" }).Count
$informationNeededControls = ($assessmentResults | Where-Object { $_.Result -eq "INFORMATION NEEDED" -or $_.Result -eq "NOT APPLICABLE" }).Count
$nonCompliantControls = $totalControls - $compliantControls - $partiallyCompliantControls - $informationNeededControls
$assessableControls = $totalControls - $informationNeededControls
if ($assessableControls -gt 0) {
    $compliancePercentage = [math]::Round(($compliantControls / $assessableControls) * 100, 2)
} else {
    $compliancePercentage = 0
}

# Display summary
Write-Host "`n=============== Assessment Summary ===============" -ForegroundColor Cyan
Write-Host "Total Controls: $totalControls"
Write-Host "Compliant: $compliantControls" -ForegroundColor Green
if ($partiallyCompliantControls -gt 0) {
    Write-Host "Partially Compliant: $partiallyCompliantControls" -ForegroundColor Yellow
}
Write-Host "Non-Compliant: $nonCompliantControls" -ForegroundColor Red
if ($informationNeededControls -gt 0) {
    Write-Host "Information Needed/Not Applicable: $informationNeededControls" -ForegroundColor Cyan
}
$complianceColor = if ($compliancePercentage -ge 80) { "Green" } elseif ($compliancePercentage -ge 60) { "Yellow" } else { "Red" }
Write-Host "Overall Compliance: $compliancePercentage%" -ForegroundColor $complianceColor
Write-Host "=================================================" -ForegroundColor Cyan

# Report location
Write-Host "`nDetailed HTML report generated at: $reportPath" -ForegroundColor Green
Write-Host "CSV report generated at: $csvPath" -ForegroundColor Green
if (Test-Path $evidencePath) {
    Write-Host "Additional evidence files saved in: $evidencePath" -ForegroundColor Green
}

# Try to open the HTML report automatically
try {
    Write-Host "`nAttempting to open the HTML report..." -ForegroundColor Cyan
    Start-Process $reportPath
} catch {
    Write-Host "Could not automatically open the report. Please open it manually." -ForegroundColor Yellow
}

Write-Host "`nAssessment completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
#endregion