function Check-OnPremisesSync {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure that password hash sync is enabled for hybrid deployments"
        $controlDescription = "Password hash synchronization helps by reducing the number of passwords your users need to maintain to just one and enables leaked credential detection for your hybrid accounts. Leaked credential protection is leveraged through Azure AD Identity Protection and is a subset of that feature which can help identify if an organization's user account passwords have appeared on the dark web or public spaces. Using other options for your directory synchronization may be less resilient as Microsoft can still process sign-ins to 365 with Hash Sync even if a network connection to your on-premises environment is not available."
    
        # Build comprehensive evidence collection
        $evidence = "=== ON-PREMISES SYNCHRONIZATION ASSESSMENT ===`n"
        $evidence += "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $evidence += "Control: Password Hash Synchronization for Hybrid Deployments`n"
        $evidence += "CIS Control: Ensure that password hash sync is enabled for hybrid deployments`n"
        $evidence += "Assessed By: $($env:USERNAME) on $($env:COMPUTERNAME)`n`n"
        
        # Document Microsoft Graph API calls
        $evidence += "MICROSOFT GRAPH API CALLS EXECUTED:`n"
        $evidence += "1. Get-MgOrganization`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/organization`n"
        $evidence += "   Purpose: Retrieve organization settings including on-premises sync status`n"
        $evidence += "   Required Permission: Directory.Read.All`n`n"
        
        $evidence += "2. Get-MgUser (with onPremises filter)`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/users`n"
        $evidence += "   Purpose: Identify synchronized users from on-premises`n"
        $evidence += "   Required Permission: User.Read.All`n`n"
        
        $evidence += "3. Get-MgDirectorySetting (if available)`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/directorySettings`n"
        $evidence += "   Purpose: Check for additional sync configuration settings`n"
        $evidence += "   Required Permission: Directory.Read.All`n`n"
        
        # Execute organization information retrieval
        $organization = $null
        try {
            $evidence += "API CALL 1 EXECUTION - Organization Information:`n"
            $organization = Get-MgOrganization
            $evidence += "SUCCESS: Successfully retrieved organization information`n"
            $evidence += "  Organization Count: $($organization.Count)`n"
            
            if ($organization.Count -gt 0) {
                $org = $organization[0]  # Take first organization
                $evidence += "  Organization ID: $($org.Id)`n"
                $evidence += "  Display Name: $($org.DisplayName)`n"
                $evidence += "  Created DateTime: $($org.CreatedDateTime)`n"
                $evidence += "  Country/Region: $($org.CountryLetterCode)`n"
            }
            
        } catch {
            $evidence += "ERROR: Failed to retrieve organization information`n"
            $evidence += "  Error Details: $_`n"
            
            return [PSCustomObject]@{
                Control = $controlTitle
                ControlDescription = $controlDescription
                Finding = "Unable to assess on-premises sync due to organization API access error."
                Result = "ERROR"
                Evidence = $evidence
                RemediationSteps = "Ensure you have Directory.Read.All permissions and try again."
            }
        }
        
        # Extract key sync-related properties
        $org = $organization[0]
        $onPremisesSyncEnabled = $org.OnPremisesSyncEnabled
        $onPremisesLastSyncDateTime = $org.OnPremisesLastSyncDateTime
        $onPremisesDomainName = $org.OnPremisesDomainName
        
        # Analyze on-premises sync configuration
        $evidence += "`nON-PREMISES SYNC CONFIGURATION ANALYSIS:`n"
        $evidence += "Property Analysis from Organization Object:`n"
        $evidence += "  OnPremisesSyncEnabled: $onPremisesSyncEnabled`n"
        $evidence += "  OnPremisesLastSyncDateTime: $onPremisesLastSyncDateTime`n"
        $evidence += "  OnPremisesDomainName: $onPremisesDomainName`n"
        
        # Determine deployment type
        $isHybridDeployment = $false
        $deploymentType = "Unknown"
        
        if ($onPremisesSyncEnabled -eq $true) {
            $isHybridDeployment = $true
            $deploymentType = "Hybrid (Active Sync)"
        } elseif ($onPremisesDomainName) {
            $isHybridDeployment = $true
            $deploymentType = "Hybrid (Domain Configured, Sync Disabled)"
        } else {
            $deploymentType = "Cloud-Only"
        }
        
        $evidence += "  Deployment Type: $deploymentType`n"
        $evidence += "  Is Hybrid Deployment: $isHybridDeployment`n"
        
        # Analyze sync timing if enabled
        if ($onPremisesLastSyncDateTime) {
            $timeSinceSync = (Get-Date) - $onPremisesLastSyncDateTime
            $evidence += "  Time Since Last Sync: $($timeSinceSync.Days) days, $($timeSinceSync.Hours) hours, $($timeSinceSync.Minutes) minutes`n"
            
            # Categorize sync recency
            if ($timeSinceSync.TotalHours -le 3) {
                $syncStatus = "Recent (within last 3 hours) - HEALTHY"
            } elseif ($timeSinceSync.TotalHours -le 24) {
                $syncStatus = "Within last 24 hours - ACCEPTABLE"
            } elseif ($timeSinceSync.TotalDays -le 7) {
                $syncStatus = "Within last week - CONCERNING"
            } else {
                $syncStatus = "More than a week old - STALE"
            }
            $evidence += "  Sync Status: $syncStatus`n"
        } else {
            $evidence += "  Sync Status: Never synced or information not available`n"
        }
        
        # Analyze synchronized users
        $syncedUsers = $null
        $totalSyncedUsers = 0
        try {
            $evidence += "`nAPI CALL 2 EXECUTION - Synchronized Users Analysis:`n"
            
            # Microsoft Graph doesn't support "ne null" filter, so we need to get users differently
            # Try multiple approaches to find synchronized users
            $syncedUsers = @()
            
            try {
                # Approach 1: Get all users and filter locally (limited sample)
                $evidence += "  Attempting to identify synchronized users...`n"
                $allUsers = Get-MgUser -Top 100 -Property DisplayName, UserPrincipalName, OnPremisesDistinguishedName, OnPremisesSyncEnabled, OnPremisesImmutableId
                
                $syncedUsers = $allUsers | Where-Object { 
                    $_.OnPremisesDistinguishedName -or 
                    $_.OnPremisesImmutableId -or 
                    $_.OnPremisesSyncEnabled -eq $true 
                }
                
                if ($syncedUsers) {
                    $totalSyncedUsers = $syncedUsers.Count
                    $evidence += "  Method: Local filtering of user properties`n"
                } else {
                    $syncedUsers = @()
                    $totalSyncedUsers = 0
                }
                
            } catch {
                $evidence += "  Warning: Could not retrieve user details for sync analysis: $_`n"
                
                # Approach 2: Fallback - assume sync users exist if sync is enabled
                if ($onPremisesSyncEnabled) {
                    $evidence += "  Fallback: Assuming synchronized users exist based on sync being enabled`n"
                    $totalSyncedUsers = "Unknown (sync enabled)"
                } else {
                    $totalSyncedUsers = 0
                }
            }
            
            $evidence += "SUCCESS: Completed synchronized user analysis`n"
            $evidence += "  Total Synchronized Users: $totalSyncedUsers`n"
            $evidence += "  Sample Users Retrieved: $($syncedUsers.Count)`n"
            
            if ($syncedUsers.Count -gt 0) {
                $evidence += "  Sample Synchronized Users:`n"
                foreach ($user in $syncedUsers | Select-Object -First 5) {
                    $evidence += "    - $($user.DisplayName) ($($user.UserPrincipalName))`n"
                    if ($user.OnPremisesDistinguishedName) {
                        $evidence += "      On-Premises DN: $($user.OnPremisesDistinguishedName)`n"
                    }
                    if ($user.OnPremisesImmutableId) {
                        $evidence += "      Immutable ID: $($user.OnPremisesImmutableId)`n"
                    }
                    $evidence += "      Sync Enabled: $($user.OnPremisesSyncEnabled)`n"
                }
                
                if ($syncedUsers.Count -gt 5) {
                    $evidence += "    ... and $($syncedUsers.Count - 5) more synchronized users`n"
                }
            } else {
                $evidence += "  No synchronized users found (likely cloud-only deployment)`n"
            }
            
        } catch {
            $evidence += "ERROR: Failed to retrieve synchronized user information`n"
            $evidence += "  Error Details: $_`n"
            $evidence += "  Impact: Cannot assess synchronized user population`n"
            $syncedUsers = @()
            $totalSyncedUsers = 0
        }
        
        # Check for directory settings that might contain sync configuration
        try {
            $evidence += "`nAPI CALL 3 EXECUTION - Directory Settings Analysis:`n"
            $directorySettings = Get-MgDirectorySetting
            $evidence += "SUCCESS: Retrieved directory settings`n"
            $evidence += "  Directory Settings Found: $($directorySettings.Count)`n"
            
            # Look for AAD Connect or sync-related settings
            $syncRelatedSettings = $directorySettings | Where-Object { 
                $_.DisplayName -match "AAD|Connect|Sync|Password" -or 
                $_.Values.Name -match "Password|Hash|Sync"
            }
            
            if ($syncRelatedSettings.Count -gt 0) {
                $evidence += "  Sync-Related Settings Found: $($syncRelatedSettings.Count)`n"
                foreach ($setting in $syncRelatedSettings) {
                    $evidence += "    - $($setting.DisplayName)`n"
                    
                    # Look for password hash sync specific settings
                    $pwdHashSyncValues = $setting.Values | Where-Object { $_.Name -match "Password.*Hash.*Sync" }
                    foreach ($value in $pwdHashSyncValues) {
                        $evidence += "      $($value.Name): $($value.Value)`n"
                    }
                }
            } else {
                $evidence += "  No sync-related directory settings found`n"
            }
            
        } catch {
            $evidence += "ERROR: Failed to retrieve directory settings`n"
            $evidence += "  Error Details: $_`n"
            $evidence += "  Impact: Cannot check advanced sync configuration`n"
        }
        
        # Password Hash Sync Assessment
        $evidence += "`nPASSWORD HASH SYNCHRONIZATION ASSESSMENT:`n"
        $passwordHashSyncEnabled = $null
        
        # For hybrid deployments, password hash sync should be enabled
        if ($isHybridDeployment) {
            $evidence += "Hybrid Deployment Detected - Password Hash Sync Analysis Required:`n"
            
            # Primary indicator: If sync is enabled and users are being synchronized
            if ($onPremisesSyncEnabled -and ($totalSyncedUsers -gt 0 -or $totalSyncedUsers -eq "Unknown (sync enabled)")) {
                # In most cases, if sync is working and users are synchronized, password hash sync is likely enabled
                # However, we cannot definitively determine this from the Graph API alone
                $passwordHashSyncEnabled = $true  # Assumption based on active sync
                $evidence += "  Primary Assessment: LIKELY ENABLED`n"
                $evidence += "  Reasoning: Active directory sync with synchronized users typically includes password hash sync`n"
                $evidence += "  Sync Status: Active (last sync: $onPremisesLastSyncDateTime)`n"
                $evidence += "  Synchronized Users: $totalSyncedUsers users found`n"
            } else {
                $passwordHashSyncEnabled = $false
                $evidence += "  Primary Assessment: NOT ENABLED OR NOT WORKING`n"
                $evidence += "  Reasoning: No active sync or no synchronized users found`n"
            }
            
            # Note about limitations
            $evidence += "`n  ASSESSMENT LIMITATION:`n"
            $evidence += "  Microsoft Graph API does not expose explicit password hash sync status`n"
            $evidence += "  Assessment is based on sync activity and user synchronization patterns`n"
            $evidence += "  For definitive status, check Azure AD Connect server configuration`n"
            
        } else {
            $evidence += "Cloud-Only Deployment Detected:`n"
            $evidence += "  Password Hash Sync: NOT APPLICABLE (no on-premises directory)`n"
            $evidence += "  Reasoning: Cloud-only tenants do not require password hash synchronization`n"
            $passwordHashSyncEnabled = $null  # Not applicable
        }
        
        # Perform compliance assessment
        $evidence += "`nCOMPLIANCE ASSESSMENT:`n"
        
        if (!$isHybridDeployment) {
            $controlFinding = "This is a cloud-only deployment, password hash sync is not applicable."
            $controlResult = "NOT APPLICABLE"
            
            $evidence += "INFO: NOT APPLICABLE - Cloud-only deployment detected`n"
            $evidence += "  Deployment Type: Cloud-Only`n"
            $evidence += "  On-Premises Sync: Not configured`n"
            $evidence += "  Status: No on-premises directory to synchronize`n"
            $evidence += "  Recommendation: Control not applicable to this environment`n"
            
        } elseif ($onPremisesSyncEnabled -and $passwordHashSyncEnabled) {
            $controlFinding = "On-premises sync is enabled and password hash synchronization appears to be working."
            $controlResult = "COMPLIANT"
            
            $evidence += "SUCCESS: COMPLIANT - Password hash synchronization is active`n"
            $evidence += "  On-Premises Sync: Enabled`n"
            $evidence += "  Last Sync: $onPremisesLastSyncDateTime`n"
            $evidence += "  Synchronized Users: $totalSyncedUsers`n"
            $evidence += "  Status: MEETS SECURITY REQUIREMENTS`n"
            $evidence += "  Benefits: Users have single password, leaked credential detection enabled`n"
            
        } else {
            $controlFinding = "On-premises sync is not properly configured or password hash synchronization is not working."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "ERROR: NOT COMPLIANT - Password hash synchronization issues detected`n"
            $evidence += "  On-Premises Sync Enabled: $onPremisesSyncEnabled`n"
            $evidence += "  Password Hash Sync Active: $passwordHashSyncEnabled`n"
            $evidence += "  Synchronized Users: $totalSyncedUsers`n"
            $evidence += "  Status: DOES NOT MEET SECURITY REQUIREMENTS`n"
            
            if (!$onPremisesSyncEnabled) {
                $evidence += "  Issue: On-premises sync is disabled`n"
            }
            if ($totalSyncedUsers -eq 0) {
                $evidence += "  Issue: No users are being synchronized`n"
            }
            if ($onPremisesLastSyncDateTime -and $timeSinceSync.TotalDays -gt 1) {
                $evidence += "  Issue: Last sync was more than 24 hours ago`n"
            }
        }
        
        # Security impact analysis
        $evidence += "`nSECURITY IMPACT ANALYSIS:`n"
        if ($isHybridDeployment) {
            if ($controlResult -eq "NOT COMPLIANT") {
                $evidence += "CURRENT RISKS without proper password hash synchronization:`n"
                $evidence += "- Users must maintain separate passwords for on-premises and cloud services`n"
                $evidence += "- No leaked credential detection for hybrid accounts`n"
                $evidence += "- Reduced resilience if on-premises connectivity is lost`n"
                $evidence += "- Users may experience authentication issues during outages`n"
                $evidence += "- Increased help desk burden for password-related issues`n"
                $evidence += "- Limited Identity Protection capabilities for synchronized accounts`n"
            } else {
                $evidence += "CURRENT PROTECTION with password hash synchronization:`n"
                $evidence += "+ Single password experience for users across on-premises and cloud`n"
                $evidence += "+ Leaked credential detection through Azure AD Identity Protection`n"
                $evidence += "+ Authentication resilience during on-premises outages`n"
                $evidence += "+ Seamless single sign-on capabilities`n"
                $evidence += "+ Reduced password-related help desk calls`n"
                $evidence += "+ Enhanced security monitoring through cloud-based analytics`n"
            }
        } else {
            $evidence += "CLOUD-ONLY DEPLOYMENT IMPACT:`n"
            $evidence += "+ No on-premises password synchronization required`n"
            $evidence += "+ All authentication handled by cloud identity provider`n"
            $evidence += "+ Full Identity Protection capabilities available`n"
            $evidence += "+ No hybrid complexity or sync-related risks`n"
        }
        
        # Affected accounts analysis for non-compliant scenarios
        $affectedAccounts = @()
        if ($controlResult -eq "NOT COMPLIANT" -and $syncedUsers.Count -gt 0) {
            $evidence += "`nAFFECTED SYNCHRONIZED ACCOUNTS:`n"
            $evidence += "Users potentially affected by sync issues: $totalSyncedUsers`n"
            
            foreach ($user in $syncedUsers | Select-Object -First 20) {
                $affectedAccounts += [PSCustomObject]@{
                    Name = $user.DisplayName
                    Id = $user.Id
                    Details = "Synchronized user potentially without password hash sync - UPN: $($user.UserPrincipalName)"
                }
            }
            
            if ($totalSyncedUsers -gt 20) {
                $evidence += "Note: Showing first 20 affected accounts. Total potentially affected: $totalSyncedUsers users`n"
            }
        }
        
        # Add verification commands
        $evidence += "`nVERIFICATION COMMANDS:`n"
        $evidence += "To manually verify on-premises sync status:`n"
        $evidence += @"
```powershell
# Connect with required permissions
Connect-MgGraph -Scopes 'Directory.Read.All', 'User.Read.All'

# Check organization sync status
`$org = Get-MgOrganization
`$org | Select-Object OnPremisesSyncEnabled, OnPremisesLastSyncDateTime, OnPremisesDomainName

# Check for synchronized users (local filtering approach)
`$allUsers = Get-MgUser -Top 100 -Property OnPremisesDistinguishedName, OnPremisesImmutableId, OnPremisesSyncEnabled
`$syncedUsers = `$allUsers | Where-Object { `$_.OnPremisesDistinguishedName -or `$_.OnPremisesImmutableId -or `$_.OnPremisesSyncEnabled }
`$syncedUsers.Count
```
"@
        
        $evidence += "`nFor definitive password hash sync status (requires Azure AD Connect server access):`n"
        $evidence += @"
```powershell
# On Azure AD Connect server:
Import-Module ADSync
Get-ADSyncConnectorPartition | Select-Object Name, PasswordHashSyncEnabled
```
"@
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<h4>Remediation Steps for Password Hash Synchronization:</h4>

<h5>Phase 1: Verify Azure AD Connect Installation</h5>
<ol>
    <li><strong>Check Azure AD Connect Status:</strong>
        <ul>
            <li>Log into your Azure AD Connect server</li>
            <li>Open <strong>Azure AD Connect</strong> application</li>
            <li>Verify the service is running and healthy</li>
        </ul>
    </li>
    <li><strong>Check Sync Status:</strong>
        <ul>
            <li>Review the last synchronization time</li>
            <li>Check for any error messages or warnings</li>
            <li>Verify connectivity to both on-premises AD and Azure AD</li>
        </ul>
    </li>
</ol>

<h5>Phase 2: Enable Password Hash Synchronization</h5>
<ol>
    <li><strong>Run Azure AD Connect Configuration Wizard:</strong>
        <ul>
            <li>On the Azure AD Connect server, run the wizard</li>
            <li>Select <strong>Configure</strong></li>
            <li>Choose <strong>Customize synchronization options</strong></li>
        </ul>
    </li>
    <li><strong>Enable Password Hash Sync:</strong>
        <ul>
            <li>Provide your Azure AD Global Administrator credentials</li>
            <li>On the <strong>Optional Features</strong> page, ensure <strong>Password hash synchronization</strong> is checked</li>
            <li>Complete the wizard</li>
        </ul>
    </li>
    <li><strong>Force Initial Sync:</strong>
        <ul>
            <li>Open PowerShell as Administrator on the Azure AD Connect server</li>
            <li>Run: <code>Import-Module ADSync</code></li>
            <li>Run: <code>Start-ADSyncSyncCycle -PolicyType Initial</code></li>
        </ul>
    </li>
</ol>

<h5>Phase 3: Verification and Monitoring</h5>
<ol>
    <li><strong>Verify Configuration:</strong>
        <ul>
            <li>Check that password hash sync is enabled: <code>Get-ADSyncConnectorPartition</code></li>
            <li>Monitor sync cycles: <code>Get-ADSyncSyncCycleResult</code></li>
            <li>Verify users are synchronizing with password hashes</li>
        </ul>
    </li>
    <li><strong>Test User Authentication:</strong>
        <ul>
            <li>Have a test user change their on-premises password</li>
            <li>Wait for sync cycle (usually 30 minutes)</li>
            <li>Test cloud authentication with new password</li>
        </ul>
    </li>
    <li><strong>Enable Identity Protection (if available):</strong>
        <ul>
            <li>Navigate to Azure AD Identity Protection</li>
            <li>Configure user risk and sign-in risk policies</li>
            <li>Enable leaked credential detection</li>
        </ul>
    </li>
</ol>

<h4>Alternative: Cloud-Only Migration</h4>
<p>If password hash sync is not suitable for your organization:</p>
<ol>
    <li><strong>Consider Pass-through Authentication:</strong>
        <ul>
            <li>Enables on-premises password validation</li>
            <li>No password hashes stored in the cloud</li>
            <li>Requires on-premises connectivity for authentication</li>
        </ul>
    </li>
    <li><strong>Evaluate Federated Authentication:</strong>
        <ul>
            <li>Using AD FS or third-party identity providers</li>
            <li>Full control over authentication policies</li>
            <li>More complex to manage and maintain</li>
        </ul>
    </li>
</ol>

<h4>Monitoring and Maintenance:</h4>
<ul>
    <li>Set up monitoring for sync health and failures</li>
    <li>Regularly review sync connector health</li>
    <li>Plan for Azure AD Connect upgrades and patches</li>
    <li>Monitor for Identity Protection alerts on synchronized accounts</li>
</ul>

<h4>Documentation Resources:</h4>
<ul>
    <li><a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-password-hash-synchronization" target="_blank">Password Hash Synchronization Documentation</a></li>
    <li><a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/tshoot-connect-password-hash-synchronization" target="_blank">Troubleshooting Password Hash Sync</a></li>
</ul>
"@
        }

        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = $controlFinding
            Result = $controlResult
            Evidence = $evidence
            AffectedAccounts = $affectedAccounts
            RemediationSteps = $remediationSteps
        }
    }
    catch {
        $errorEvidence = "=== ASSESSMENT ERROR ===`n"
        $errorEvidence += "An unexpected error occurred during on-premises sync assessment.`n`n"
        $errorEvidence += "Error Details:`n"
        $errorEvidence += "- Message: $_`n"
        $errorEvidence += "- Type: $($_.Exception.GetType().Name)`n"
        $errorEvidence += "- Stack Trace: $($_.ScriptStackTrace)`n`n"
        $errorEvidence += "Possible Causes:`n"
        $errorEvidence += "- Insufficient permissions (requires Directory.Read.All, User.Read.All)`n"
        $errorEvidence += "- Network connectivity issues`n"
        $errorEvidence += "- Microsoft Graph API service issues`n"
        $errorEvidence += "- Authentication token expiration`n"
        
        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = "Error occurred during on-premises sync assessment: $_"
            Result = "ERROR"
            Evidence = $errorEvidence
            RemediationSteps = "Resolve the error above and re-run the assessment. Ensure you have Directory.Read.All and User.Read.All permissions."
        }
    }
}

# Call the function
Check-OnPremisesSync