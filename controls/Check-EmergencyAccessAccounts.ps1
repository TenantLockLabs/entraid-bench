function Check-EmergencyAccessAccounts {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure emergency access accounts are properly configured"
        $controlDescription = "Emergency access accounts (break glass accounts) are critical for recovering access when normal administrative accounts cannot authenticate. These accounts should be carefully managed, not require MFA, and have appropriate permissions. Microsoft recommends having at least two properly configured emergency access accounts."
        
        # Look for potential emergency access accounts using multiple filter queries
        # Microsoft Graph OData filters have limitations, so we'll use separate calls
        $potentialEmergencyAccounts = @()
        
        try {
            # Search for accounts with 'emergency' in display name
            $emergencyByDisplayName = Get-MgUser -Filter "startswith(displayName,'emergency')" -Property Id, DisplayName, UserPrincipalName, AccountEnabled -ErrorAction SilentlyContinue
            if ($emergencyByDisplayName) {
                $potentialEmergencyAccounts += $emergencyByDisplayName
            }
        } catch {
            # Ignore filter errors and try alternative approach
        }
        
        try {
            # Search for accounts with 'break' in display name
            $breakByDisplayName = Get-MgUser -Filter "startswith(displayName,'break')" -Property Id, DisplayName, UserPrincipalName, AccountEnabled -ErrorAction SilentlyContinue
            if ($breakByDisplayName) {
                $potentialEmergencyAccounts += $breakByDisplayName
            }
        } catch {
            # Ignore filter errors
        }
        
        try {
            # Search for accounts with 'emergency' in UPN
            $emergencyByUPN = Get-MgUser -Filter "startswith(userPrincipalName,'emergency')" -Property Id, DisplayName, UserPrincipalName, AccountEnabled -ErrorAction SilentlyContinue
            if ($emergencyByUPN) {
                $potentialEmergencyAccounts += $emergencyByUPN
            }
        } catch {
            # Ignore filter errors
        }
        
        try {
            # Search for accounts with 'break' in UPN
            $breakByUPN = Get-MgUser -Filter "startswith(userPrincipalName,'break')" -Property Id, DisplayName, UserPrincipalName, AccountEnabled -ErrorAction SilentlyContinue
            if ($breakByUPN) {
                $potentialEmergencyAccounts += $breakByUPN
            }
        } catch {
            # Ignore filter errors
        }
        
        # If filters don't work, fall back to getting all users and filtering locally
        if ($potentialEmergencyAccounts.Count -eq 0) {
            try {
                Write-Host "  Searching through user accounts for emergency patterns..." -ForegroundColor Yellow
                $allUsers = Get-MgUser -Top 1000 -Property Id, DisplayName, UserPrincipalName, AccountEnabled
                $potentialEmergencyAccounts = $allUsers | Where-Object { 
                    $_.DisplayName -match "emergency|break|glass" -or 
                    $_.UserPrincipalName -match "emergency|break|glass"
                }
            } catch {
                Write-Host "  Unable to search for emergency accounts due to permissions" -ForegroundColor Yellow
            }
        }
        
        # Remove duplicates based on Id
        $potentialEmergencyAccounts = $potentialEmergencyAccounts | Sort-Object Id -Unique
        
        # Check for service principals named similarly
        $emergencyServicePrincipals = @()
        try {
            $emergencyServicePrincipals += Get-MgServicePrincipal -Filter "startswith(displayName,'emergency')" -Property Id, DisplayName, AppId -ErrorAction SilentlyContinue
            $emergencyServicePrincipals += Get-MgServicePrincipal -Filter "startswith(displayName,'break')" -Property Id, DisplayName, AppId -ErrorAction SilentlyContinue
            # Remove duplicates
            $emergencyServicePrincipals = $emergencyServicePrincipals | Sort-Object Id -Unique
        } catch {
            # Service principal search failed - continue without it
        }
        
        $evidence = "Emergency Access Account Configuration:`n"
        
        if ($potentialEmergencyAccounts.Count -eq 0 -and $emergencyServicePrincipals.Count -eq 0) {
            $controlFinding = "No emergency access accounts detected."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "`nNo accounts matching emergency access naming patterns were found in your tenant."
            $evidence += "`n`nEmergency access accounts are crucial for recovery when:
- Multi-factor authentication (MFA) is unavailable
- Identity federation services fail
- Administrator accounts are locked out
- Administrative credentials are lost or compromised"
            
            $evidence += "`n`nRecommended naming patterns to search for:
- emergency*, break*, *glass*
- admin-emergency*, breakglass*
- bg-*, ea-*"
        }
        else {
            # Check if these accounts have the right characteristics
            $hasValidEmergencyAccounts = $false
            $affectedAccounts = @()
            
            $evidence += "`nPotential Emergency Access Accounts Found: $($potentialEmergencyAccounts.Count)`n"
            
            foreach ($account in $potentialEmergencyAccounts) {
                $evidence += "`n- $($account.DisplayName) ($($account.UserPrincipalName))"
                $evidence += "`n  Enabled: $($account.AccountEnabled)"
                
                # Check role assignments
                try {
                    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($account.Id)'" -ErrorAction SilentlyContinue
                    if ($roleAssignments) {
                        $evidence += "`n  Has role assignments: Yes"
                        $hasValidEmergencyAccounts = $true
                        
                        # Retrieve role details
                        foreach ($assignment in $roleAssignments) {
                            try {
                                $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId -ErrorAction SilentlyContinue
                                if ($role) {
                                    $evidence += "`n    Role: $($role.DisplayName)"
                                    # Check if it's a privileged role
                                    if ($role.DisplayName -match "Global Administrator|Privileged Role Administrator|Security Administrator") {
                                        $hasValidEmergencyAccounts = $true
                                    }
                                }
                            } catch {
                                $evidence += "`n    Role: Unknown (ID: $($assignment.RoleDefinitionId))"
                            }
                        }
                    } else {
                        $evidence += "`n  Has role assignments: No (emergency accounts should have Global Administrator or equivalent role)"
                    }
                } catch {
                    $evidence += "`n  Unable to check role assignments: $_"
                }
                
                # Check MFA methods - emergency accounts typically shouldn't require MFA
                try {
                    $authMethods = Get-MgUserAuthenticationMethod -UserId $account.Id -ErrorAction SilentlyContinue
                    if ($authMethods) {
                        $evidence += "`n  Authentication methods: $($authMethods.Count)"
                        
                        # List the types of authentication methods
                        $methodTypes = $authMethods | ForEach-Object { 
                            $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
                        }
                        $evidence += "`n  Method types: $($methodTypes -join ', ')"
                    }
                } catch {
                    $evidence += "`n  Unable to retrieve authentication methods"
                }
                
                # Check if account is excluded from CA policies requiring MFA
                try {
                    $caExclusions = $false
                    $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "enabled" }
                    
                    foreach ($policy in $caPolicies) {
                        if ($policy.Conditions.Users.ExcludeUsers -contains $account.Id) {
                            $caExclusions = $true
                            $evidence += "`n  Excluded from CA policy: $($policy.DisplayName)"
                        }
                    }
                    
                    if (-not $caExclusions -and $caPolicies.Count -gt 0) {
                        $evidence += "`n  WARNING: Account may not be excluded from MFA requirements in Conditional Access policies"
                    }
                } catch {
                    $evidence += "`n  Unable to check Conditional Access exclusions"
                }
                
                # Add to affected accounts for tracking
                $affectedAccounts += [PSCustomObject]@{
                    Name = $account.DisplayName
                    Id = $account.Id
                    Details = "Potential emergency access account - UPN: $($account.UserPrincipalName)"
                }
                
                $evidence += "`n"
            }
            
            # Check service principals
            if ($emergencyServicePrincipals.Count -gt 0) {
                $evidence += "`nEmergency Service Principals Found: $($emergencyServicePrincipals.Count)`n"
                foreach ($sp in $emergencyServicePrincipals) {
                    $evidence += "`n- $($sp.DisplayName) (AppId: $($sp.AppId))"
                }
            }
            
            # Determine final status
            if ($hasValidEmergencyAccounts) {
                # Check if we have at least two accounts
                if ($potentialEmergencyAccounts.Count -ge 2) {
                    $controlFinding = "Multiple emergency access accounts appear to be properly configured."
                    $controlResult = "COMPLIANT"
                    
                    $evidence += "`n`nEmergency access accounts are present with appropriate configurations. Having multiple emergency accounts provides redundancy in case one becomes unavailable."
                } else {
                    $controlFinding = "Only one emergency access account detected. Microsoft recommends at least two."
                    $controlResult = "PARTIALLY COMPLIANT"
                    
                    $evidence += "`n`nOnly one emergency access account was found. Microsoft recommends at least two emergency access accounts to ensure redundancy."
                }
            } else {
                $controlFinding = "Potential emergency access accounts exist but may not be properly configured."
                $controlResult = "NOT COMPLIANT"
                
                $evidence += "`n`nAccounts with emergency access naming patterns were found, but they may not be properly configured as break glass accounts. Ensure they have:
- Global Administrator or equivalent privileged role
- Exclusion from MFA requirements in Conditional Access policies
- Strong passwords and secure credential storage
- Proper documentation and access procedures"
            }
        }
        
        # Add remediation steps
        $remediationSteps = $null
        if ($controlResult -ne "COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Create at least two cloud-only emergency access accounts with these characteristics:
        <ul>
            <li><strong>Naming:</strong> Use clear naming like "emergency-admin-01" and "emergency-admin-02"</li>
            <li><strong>Role Assignment:</strong> Assign Global Administrator role</li>
            <li><strong>Authentication:</strong> Use very strong passwords (20+ characters) but do NOT set up MFA</li>
            <li><strong>Account Type:</strong> Ensure they are cloud-only accounts (not synchronized from on-premises)</li>
            <li><strong>Storage:</strong> Store credentials securely (e.g., in a physical safe, split between multiple trusted individuals)</li>
        </ul>
    </li>
    <li>Exclude these accounts from Conditional Access policies:
        <ul>
            <li>Navigate to <strong>Protection > Conditional Access</strong> in the Microsoft Entra admin center</li>
            <li>For each policy that enforces MFA or other restrictions:</li>
            <li>Edit the policy and go to <strong>Users and groups</strong></li>
            <li>Under <strong>Exclude</strong>, add your emergency access accounts</li>
            <li>Save the policy</li>
        </ul>
    </li>
    <li>Document and test emergency procedures:
        <ul>
            <li>Create written procedures for when and how to use these accounts</li>
            <li>Document who has access to the credentials</li>
            <li>Establish a regular testing schedule (quarterly recommended)</li>
            <li>Set up monitoring and alerting when these accounts are used</li>
        </ul>
    </li>
    <li>Monitor emergency account usage:
        <ul>
            <li>Set up alerts in Azure Monitor or Microsoft Sentinel</li>
            <li>Review sign-in logs regularly</li>
            <li>Investigate any unexpected usage immediately</li>
        </ul>
    </li>
</ol>

<p><strong>Important:</strong> Emergency access accounts should only be used during actual emergencies when normal administrative access is unavailable. Regular use of these accounts defeats their purpose and creates security risks.</p>

<p>For detailed guidance, see <a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access" target="_blank">Microsoft's documentation on emergency access accounts</a>.</p>
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
        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = "Error occurred while checking emergency access accounts: $_"
            Result = "ERROR"
            Evidence = "An error occurred during the assessment. This may be due to insufficient permissions or connectivity issues."
        }
    }
}

# Call the function to run the check
Check-EmergencyAccessAccounts