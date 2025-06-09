function Check-ControlScore {
    $controlNames = @(
        'UserRiskPolicy',
        'aad_admin_consent_workflow',
        'aad_limited_administrative_roles',
        'aad_linkedin_connection_disables',
        'aad_password_protection',
        'aad_sign_in_freq_session_timeout',
        'aad_third_party_apps',
        'IntegratedApps',
        'BlockLegacyAuthentication',
        'SelfServicePasswordReset',
        'SigninRiskPolicy',
        'adminMFAV2',
        'mfaRegistrationV2'
    )

    # Initialize progress bar parameters
    $totalControls = $controlNames.Count
    $completedControls = 8

    $results = @()

    try {
        # Check if Secure Score is available
        $secureScore = Get-MgSecuritySecureScore -Top 1 -ErrorAction Stop
        
        if (-not $secureScore) {
            Write-Host "  Secure Score data not available in this tenant" -ForegroundColor Yellow
            
            return [PSCustomObject]@{
                Control = "Microsoft Secure Score Controls"
                ControlDescription = "Multiple security controls assessed via Microsoft Secure Score API"
                Finding = "Microsoft Secure Score data is not available in this tenant. This may be due to licensing requirements or tenant configuration."
                Result = "INFORMATION NEEDED"
                Evidence = "Microsoft Secure Score requires specific licensing and configuration. Manual assessment of individual controls may be required."
            }
        }

        $controlScores = $secureScore.ControlScores
        
        if (-not $controlScores -or $controlScores.Count -eq 0) {
            Write-Host "  No control scores available in Secure Score" -ForegroundColor Yellow
            
            return [PSCustomObject]@{
                Control = "Microsoft Secure Score Controls"
                ControlDescription = "Multiple security controls assessed via Microsoft Secure Score API"
                Finding = "No control scores are available in Microsoft Secure Score for this tenant."
                Result = "INFORMATION NEEDED"
                Evidence = "Microsoft Secure Score may not be configured or may require additional time to populate data for a new tenant."
            }
        }

    } catch {
        Write-Host "  Error accessing Secure Score: $_" -ForegroundColor Red
        
        return [PSCustomObject]@{
            Control = "Microsoft Secure Score Controls"
            ControlDescription = "Multiple security controls assessed via Microsoft Secure Score API"
            Finding = "Unable to access Microsoft Secure Score data due to permissions or configuration issues."
            Result = "ERROR"
            Evidence = "Error details: $($_.Exception.Message). This may require SecurityEvents.Read.All permissions or specific licensing."
        }
    }

    foreach ($controlName in $controlNames) {
        try {
            $controlScore = $controlScores | Where-Object { $_.ControlName -eq $controlName }
            
            if (-not $controlScore) {
                Write-Host "  Control '$controlName' not found in Secure Score" -ForegroundColor Yellow
                continue
            }
            
            # Get control profile for friendly name and description
            $controlProfileName = $controlName
            $controlDescription = "Security control assessed via Microsoft Secure Score"
            
            try {
                if ($controlName -eq "mfaRegistrationV2") {
                    $controlProfileName = "Ensure multifactor authentication is enabled for all users"
                }
                elseif ($controlName -eq "adminMFAV2") {
                    $controlProfileName = "Ensure multifactor authentication is enabled for all users in administrative roles"
                }
                else {
                    $controlProfile = Get-MgSecuritySecureScoreControlProfile -SecureScoreControlProfileId $controlName -ErrorAction SilentlyContinue
                    if ($controlProfile) {
                        $controlProfileName = $controlProfile.Title
                        $controlDescription = $controlProfile.Description
                    }
                }
            } catch {
                # Use default names if profile retrieval fails
                Write-Host "  Could not retrieve profile for control '$controlName'" -ForegroundColor Yellow
            }

            # Update progress bar
            $completedControls++
            $progressBar = '=' * $completedControls + ' ' * (21 - $completedControls)
            Write-Host "Checking Control: $progressBar ($completedControls of 21): $controlProfileName"

            # Extract control information safely
            $additionalProperties = $controlScore.AdditionalProperties
            
            $controlFinding = if ($additionalProperties -and $additionalProperties.ContainsKey('implementationStatus')) {
                $additionalProperties['implementationStatus']
            } else {
                "Status information not available"
            }
            
            $controlCount = if ($additionalProperties -and $additionalProperties.ContainsKey('count')) {
                $additionalProperties['count']
            } else {
                "N/A"
            }
            
            $controlTotal = if ($additionalProperties -and $additionalProperties.ContainsKey('total')) {
                $additionalProperties['total']
            } else {
                "N/A"
            }
            
            $controlScoreInPercentage = if ($additionalProperties -and $additionalProperties.ContainsKey('scoreInPercentage')) {
                $additionalProperties['scoreInPercentage']
            } else {
                "0"
            }

            # Determine compliance result
            $complianceResult = if ($controlScoreInPercentage -eq "100" -or $controlScoreInPercentage -eq "100.00") { 
                "COMPLIANT" 
            } else { 
                "NOT COMPLIANT" 
            }

            $results += [PSCustomObject]@{
                Control = $controlProfileName
                ControlDescription = $controlDescription
                Finding = $controlFinding
                Result = $complianceResult
                Evidence = "Score: $controlScoreInPercentage% ($controlCount of $controlTotal items compliant)"
            }
        } catch {
            Write-Host "  Error processing control '$controlName': $_" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                Control = $controlName
                ControlDescription = "Security control from Microsoft Secure Score"
                Finding = "Error retrieving control data: $_"
                Result = "ERROR"
                Evidence = "Unable to process this control due to an error."
            }
        }
    }
    
    return $results
}

# Call the function with the array of control names
Check-ControlScore