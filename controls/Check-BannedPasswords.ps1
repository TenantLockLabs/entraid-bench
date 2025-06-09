function Check-BannedPasswordSettings {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure custom banned passwords lists are used"
        $controlDescription = "Creating a new password can be difficult regardless of one's technical background. It is common to look around one's environment for suggestions when building a password, however, this may include picking words specific to the organization as inspiration for a password. An adversary may employ what is called a 'mangler' to create permutations of these specific words in an attempt to crack passwords or hashes making it easier to reach their goal."
    
        # Build detailed evidence collection
        $evidence = "=== BANNED PASSWORDS ASSESSMENT EVIDENCE ===`n"
        $evidence += "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $evidence += "Control: Custom Banned Passwords Configuration`n`n"
        
        # Document the commands we're running
        $evidence += "COMMANDS EXECUTED:`n"
        $evidence += "1. Get-MgGroupSetting`n"
        $evidence += "   Purpose: Retrieve organization-wide password policy settings`n`n"
        
        # Retrieve the group setting with error handling
        $groupSetting = $null
        try {
            $evidence += "COMMAND OUTPUT:`n"
            $groupSetting = Get-MgGroupSetting
            
            if ($groupSetting) {
                $evidence += "SUCCESS: Successfully retrieved group settings`n"
                $evidence += "  Number of settings objects returned: $($groupSetting.Count)`n"
                
                # Show the setting template information
                if ($groupSetting.Count -gt 0) {
                    $evidence += "  Settings templates found:`n"
                    foreach ($setting in $groupSetting) {
                        $evidence += "    - Template ID: $($setting.TemplateId)`n"
                        $evidence += "      Display Name: $($setting.DisplayName)`n"
                        $evidence += "      Values Count: $($setting.Values.Count)`n"
                    }
                }
            } else {
                $evidence += "WARNING: No group settings returned - this may indicate default settings are in use`n"
            }
        } catch {
            $evidence += "ERROR: Failed to retrieve group settings - $_`n"
            
            return [PSCustomObject]@{
                Control = $controlTitle
                ControlDescription = $controlDescription
                Finding = "Unable to assess banned passwords due to API error."
                Result = "ERROR"
                Evidence = $evidence + "`n`nThis error may be due to insufficient permissions or tenant configuration issues."
                RemediationSteps = "Ensure you have Directory.Read.All permissions and try again."
                AffectedAccounts = @()
            }
        }
        
        $evidence += "`n"
        
        # Find the banned password settings
        $evidence += "CONFIGURATION ANALYSIS:`n"
        $enableBannedPasswordCheckValue = $null
        $bannedPasswordListValue = $null
        
        # Look for the settings in the group settings
        if ($groupSetting) {
            foreach ($setting in $groupSetting) {
                if ($setting.Values) {
                    $enableBannedPasswordCheckValue = $setting.Values | Where-Object { $_.Name -eq "EnableBannedPasswordCheck" }
                    $bannedPasswordListValue = $setting.Values | Where-Object { $_.Name -eq "BannedPasswordList" }
                    
                    if ($enableBannedPasswordCheckValue -or $bannedPasswordListValue) {
                        break
                    }
                }
            }
        }
        
        # Analyze EnableBannedPasswordCheck setting
        if ($enableBannedPasswordCheckValue) {
            $evidence += "SUCCESS: Found 'EnableBannedPasswordCheck' setting`n"
            $evidence += "  Current Value: $($enableBannedPasswordCheckValue.Value)`n"
            $evidence += "  Data Type: $($enableBannedPasswordCheckValue.Value.GetType().Name)`n"
        } else {
            $evidence += "ERROR: 'EnableBannedPasswordCheck' setting not found`n"
            $evidence += "  This typically means custom banned passwords are not configured`n"
        }

        # Analyze BannedPasswordList setting
        if ($bannedPasswordListValue) {
            $evidence += "SUCCESS: Found 'BannedPasswordList' setting`n"
            
            $listStatus = "Empty"
            $passwordCount = 0
            
            if ($bannedPasswordListValue.Value) {
                $listStatus = "Contains entries"
                $passwordCount = $bannedPasswordListValue.Value.Count
            }
            
            $evidence += "  List Status: $listStatus`n"
            $evidence += "  Number of banned passwords: $passwordCount`n"
            
            # Show sample patterns (redacted for security)
            if ($bannedPasswordListValue.Value -and $bannedPasswordListValue.Value.Count -gt 0) {
                $evidence += "  Sample patterns (first 3, redacted):`n"
                $samplePasswords = $bannedPasswordListValue.Value | Select-Object -First 3
                foreach ($pwd in $samplePasswords) {
                    $redactedLength = [Math]::Min(3, $pwd.Length)
                    $redacted = $pwd.Substring(0, $redactedLength) + "*" * ($pwd.Length - $redactedLength)
                    $evidence += "    - $redacted (length: $($pwd.Length))`n"
                }
            }
        } else {
            $evidence += "ERROR: 'BannedPasswordList' setting not found`n"
            $evidence += "  This indicates no custom banned passwords are configured`n"
        }
        
        $evidence += "`n"
        
        # Determine compliance status
        $evidence += "COMPLIANCE ASSESSMENT:`n"
        
        $controlFinding = ""
        $controlResult = ""
        
        # Check if EnableBannedPasswordCheck is enabled
        $isBannedPasswordCheckEnabled = $false
        if ($enableBannedPasswordCheckValue -and $enableBannedPasswordCheckValue.Value -eq $true) {
            $isBannedPasswordCheckEnabled = $true
        }
        
        # Check if BannedPasswordList has entries
        $hasBannedPasswordEntries = $false
        if ($bannedPasswordListValue -and $bannedPasswordListValue.Value -and $bannedPasswordListValue.Value.Count -gt 0) {
            $hasBannedPasswordEntries = $true
        }
        
        # Determine compliance based on both settings
        if ($isBannedPasswordCheckEnabled) {
            $evidence += "SUCCESS: Custom banned password checking is ENABLED`n"
            
            if ($hasBannedPasswordEntries) {
                $controlFinding = "Custom banned passwords setting is enabled and the list of passwords is configured."
                $controlResult = "COMPLIANT"
                
                $evidence += "SUCCESS: COMPLIANT - Custom banned passwords properly configured`n"
                $evidence += "  Feature Status: Enabled`n"
                $evidence += "  Banned Words Count: $($bannedPasswordListValue.Value.Count)`n"
                $evidence += "  Effectiveness: Organization-specific terms are being blocked from passwords`n"
            } else {
                $controlFinding = "Custom banned passwords setting is enabled but the list of passwords is empty."
                $controlResult = "NOT COMPLIANT"
                
                $evidence += "ERROR: COMPLIANCE ISSUE - Banned password list is empty`n"
                $evidence += "  Reasoning: Having the feature enabled without any banned passwords provides no protection`n"
                $evidence += "  Risk: Users can still choose common passwords that are easily guessable`n"
                $evidence += "  Expected: A list of organization-specific terms that should be banned`n"
            }
        } else {
            $controlFinding = "Custom banned passwords setting is disabled."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "ERROR: COMPLIANCE ISSUE - Custom banned password checking is DISABLED`n"
            
            $currentSetting = "Not configured (defaults to disabled)"
            if ($enableBannedPasswordCheckValue) {
                $currentSetting = $enableBannedPasswordCheckValue.Value
            }
            
            $evidence += "  Current Setting: $currentSetting`n"
            $evidence += "  Reasoning: Without this feature, users can choose organization-specific terms as passwords`n"
            $evidence += "  Risk: Attackers can use company name, products, locations in dictionary attacks`n"
            $evidence += "  Expected: Feature should be enabled with relevant organizational terms`n"
        }
        
        $evidence += "`n"
        $evidence += "SECURITY IMPACT:`n"
        $evidence += "Custom banned passwords help prevent users from choosing passwords that include:`n"
        $evidence += "- Organization name and variations (e.g., 'Contoso123', 'contoso2024')`n"
        $evidence += "- Product names and services`n"
        $evidence += "- Office locations and city names`n"
        $evidence += "- Industry-specific terminology`n"
        $evidence += "- Common dictionary words specific to your business`n"
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<h4>Step-by-Step Remediation Instructions:</h4>
<ol>
    <li><strong>Navigate to Password Protection Settings:</strong>
        <ul>
            <li>Go to <a href="https://entra.microsoft.com" target="_blank">Microsoft Entra admin center</a></li>
            <li>Navigate to <strong>Identity > Protection > Password protection</strong></li>
        </ul>
    </li>
    <li><strong>Enable Custom Banned Password List:</strong>
        <ul>
            <li>Set <strong>Enforce custom list</strong> to <strong>Yes</strong></li>
            <li>This corresponds to the 'EnableBannedPasswordCheck' setting we checked</li>
        </ul>
    </li>
    <li><strong>Add Organization-Specific Terms:</strong>
        <ul>
            <li>In the <strong>Custom banned password list</strong> field, add terms like:</li>
            <li>Your organization's name and common variations</li>
            <li>Product or service names</li>
            <li>Office locations and city names</li>
            <li>Common industry terms</li>
            <li>Previous company names or acquisitions</li>
        </ul>
    </li>
    <li><strong>Test and Validate:</strong>
        <ul>
            <li>Save the configuration</li>
            <li>Test password creation to ensure banned terms are blocked</li>
            <li>Re-run this assessment to verify compliance</li>
        </ul>
    </li>
</ol>

<h4>Example Banned Password Terms:</h4>
<pre>
- [YourCompanyName]
- [YourCompanyName]123
- [ProductName]
- [OfficeCity]
- [IndustryTerm]
- [FormerCompanyName]
</pre>

<p><strong>Note:</strong> The system automatically checks variations and combinations of these terms, so you don't need to add every possible variation.</p>

<h4>Verification Commands:</h4>
<p>After making changes, you can verify the configuration using PowerShell:</p>
<pre>
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All"

# Check the current settings
Get-MgGroupSetting | Where-Object { $_.Values.Name -contains "EnableBannedPasswordCheck" } | 
    Select-Object -ExpandProperty Values | 
    Where-Object { $_.Name -in @("EnableBannedPasswordCheck", "BannedPasswordList") }
</pre>
"@
        }

        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = $controlFinding
            Result = $controlResult
            Evidence = $evidence
            RemediationSteps = $remediationSteps
            AffectedAccounts = @()
        }
    }
    catch {
        $errorEvidence = "=== ERROR DURING ASSESSMENT ===`n"
        $errorEvidence += "Error occurred while checking banned password settings`n"
        $errorEvidence += "Error Details: $_`n"
        $errorEvidence += "Stack Trace: $($_.ScriptStackTrace)`n"
        $errorEvidence += "This may be due to insufficient permissions or connectivity issues.`n"
        
        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = "Error occurred while checking the settings: $_"
            Result = "ERROR"
            Evidence = $errorEvidence
            RemediationSteps = "Ensure you have appropriate permissions (Directory.Read.All) and network connectivity to Microsoft Graph."
            AffectedAccounts = @()
        }
    }
}

# Call the function to check the settings
Check-BannedPasswordSettings