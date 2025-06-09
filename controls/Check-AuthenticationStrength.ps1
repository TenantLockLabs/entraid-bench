function Check-AuthenticationStrength {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure 'Phishing-resistant MFA strength' is required for Administrators"
        $controlDescription = "Authentication strength is a Conditional Access control that allows administrators to specify which combination of authentication methods can be used to access a resource. For example, they can make only phishing-resistant authentication methods available to access a sensitive resource. But to access a non-sensitive resource, they can allow less secure multifactor authentication (MFA) combinations, such as password + SMS. Microsoft has 3 built-in authentication strengths. MFA strength, Passwordless MFA strength, and Phishing-resistant MFA strength. Ensure administrator roles are using a CA policy with Phishing-resistant MFA strength."

        # Build comprehensive evidence collection
        $evidence = "=== PHISHING-RESISTANT MFA ASSESSMENT EVIDENCE ===`n"
        $evidence += "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $evidence += "Control: Phishing-Resistant MFA for Administrators`n"
        $evidence += "CIS Control: Ensure 'Phishing-resistant MFA strength' is required for Administrators`n"
        $evidence += "Assessed By: $($env:USERNAME) on $($env:COMPUTERNAME)`n`n"
        
        # Document Microsoft Graph API calls
        $evidence += "MICROSOFT GRAPH API CALLS EXECUTED:`n"
        $evidence += "1. Get-MgIdentityConditionalAccessPolicy`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`n"
        $evidence += "   Purpose: Retrieve all Conditional Access policies to analyze authentication strength requirements`n"
        $evidence += "   Required Permission: Policy.Read.All`n`n"
        
        $evidence += "2. Get-MgRoleManagementDirectoryRoleDefinition`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions`n"
        $evidence += "   Purpose: Retrieve administrator role definitions for coverage analysis`n"
        $evidence += "   Required Permission: RoleManagement.Read.All`n`n"
        
        $evidence += "3. Get-MgRoleManagementDirectoryRoleAssignment`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments`n"
        $evidence += "   Purpose: Identify users assigned to administrator roles`n"
        $evidence += "   Required Permission: RoleManagement.Read.All`n`n"
        
        # Retrieve all Conditional Access policies
        $policies = $null
        try {
            $evidence += "API CALL 1 EXECUTION - Conditional Access Policies:`n"
            $policies = Get-MgIdentityConditionalAccessPolicy | Sort-Object DisplayName
            $evidence += "SUCCESS: Successfully retrieved Conditional Access policies`n"
            $evidence += "  Total Policies Found: $($policies.Count)`n"
            $evidence += "  Policy States:`n"
            
            $enabledPolicies = $policies | Where-Object { $_.State -eq "enabled" }
            $disabledPolicies = $policies | Where-Object { $_.State -eq "disabled" }
            $reportOnlyPolicies = $policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
            
            $evidence += "    - Enabled: $($enabledPolicies.Count)`n"
            $evidence += "    - Disabled: $($disabledPolicies.Count)`n"
            $evidence += "    - Report-Only: $($reportOnlyPolicies.Count)`n"
            
        } catch {
            $evidence += "ERROR: Failed to retrieve Conditional Access policies`n"
            $evidence += "  Error Details: $_`n"
            
            return [PSCustomObject]@{
                Control = $controlTitle
                ControlDescription = $controlDescription
                Finding = "Unable to assess authentication strength due to Conditional Access API error."
                Result = "ERROR"
                Evidence = $evidence
                RemediationSteps = "Ensure you have Policy.Read.All permissions and try again."
            }
        }
        
        # Get all administrator roles for reference
        $adminRoles = $null
        try {
            $evidence += "`nAPI CALL 2 EXECUTION - Administrator Roles:`n"
            $adminRoles = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
                $_.IsBuiltIn -eq $true -and $_.DisplayName -match "Administrator"
            } | Select-Object DisplayName, Id
            $evidence += "SUCCESS: Successfully retrieved administrator role definitions`n"
            $evidence += "  Total Administrator Roles Found: $($adminRoles.Count)`n"
            $evidence += "  Administrator Roles:`n"
            
            foreach ($role in $adminRoles | Sort-Object DisplayName) {
                $evidence += "    - $($role.DisplayName) (ID: $($role.Id))`n"
            }
            
        } catch {
            $evidence += "ERROR: Failed to retrieve administrator roles`n"
            $evidence += "  Error Details: $_`n"
            $evidence += "  Impact: Cannot perform comprehensive role coverage analysis`n"
            # Continue with limited analysis
        }
        
        $evidence += "`n"
        
        # Analyze policies for phishing-resistant MFA strength
        $evidence += "AUTHENTICATION STRENGTH ANALYSIS:`n"
        $evidence += "Target Authentication Strength ID: 00000000-0000-0000-0000-000000000004 (Phishing-resistant MFA)`n"
        $evidence += "Alternative Strength IDs:`n"
        $evidence += "  - 00000000-0000-0000-0000-000000000002 (MFA strength)`n"
        $evidence += "  - 00000000-0000-0000-0000-000000000003 (Passwordless MFA strength)`n`n"
        
        $phishingResistantPolicies = @()
        $otherMfaPolicies = @()
        
        foreach ($policy in $policies) {
            $policyDetails = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
            $authenticationStrength = $policy.GrantControls.AuthenticationStrength
            
            if ($authenticationStrength) {
                $evidence += "Policy: $($policy.DisplayName)`n"
                $evidence += "  State: $($policy.State)`n"
                $evidence += "  Auth Strength ID: $($authenticationStrength.Id)`n"
                $evidence += "  Auth Strength Name: $($authenticationStrength.DisplayName)`n"
                
                # Check if policy uses phishing-resistant MFA strength
                if ($authenticationStrength.Id -eq "00000000-0000-0000-0000-000000000004") {
                    $phishingResistantPolicies += $policy
                    $evidence += "  SUCCESS: PHISHING-RESISTANT MFA POLICY DETECTED`n"
                    
                    # Analyze policy targeting
                    if ($policyDetails.Conditions.Users.IncludeRoles) {
                        $evidence += "  Target Roles: $($policyDetails.Conditions.Users.IncludeRoles.Count) roles`n"
                        foreach ($roleId in $policyDetails.Conditions.Users.IncludeRoles) {
                            $roleName = ($adminRoles | Where-Object { $_.Id -eq $roleId }).DisplayName
                            if ($roleName) {
                                $evidence += "    - $roleName`n"
                            } else {
                                $evidence += "    - Unknown Role (ID: $roleId)`n"
                            }
                        }
                    }
                    
                    if ($policyDetails.Conditions.Users.IncludeUsers) {
                        $evidence += "  Target Users: $($policyDetails.Conditions.Users.IncludeUsers.Count) specific users`n"
                    }
                    
                    if ($policyDetails.Conditions.Users.IncludeGroups) {
                        $evidence += "  Target Groups: $($policyDetails.Conditions.Users.IncludeGroups.Count) groups`n"
                    }
                    
                } elseif ($authenticationStrength.Id -in @("00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003")) {
                    $otherMfaPolicies += $policy
                    $evidence += "  WARNING: OTHER MFA STRENGTH (not phishing-resistant)`n"
                }
                
                $evidence += "`n"
            }
        }
        
        # Analyze role coverage
        $evidence += "ADMINISTRATOR ROLE COVERAGE ANALYSIS:`n"
        $coveredRoleIds = @()
        foreach ($policy in $phishingResistantPolicies) {
            $policyDetails = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
            if ($policyDetails.Conditions.Users.IncludeRoles) {
                $coveredRoleIds += $policyDetails.Conditions.Users.IncludeRoles
            }
        }
        
        # Remove duplicates
        $coveredRoleIds = $coveredRoleIds | Sort-Object -Unique
        $uncoveredAdminRoles = $adminRoles | Where-Object { $coveredRoleIds -notcontains $_.Id }
        
        $evidence += "Roles Covered by Phishing-Resistant MFA Policies: $($coveredRoleIds.Count)`n"
        $evidence += "Roles NOT Covered: $($uncoveredAdminRoles.Count)`n"
        
        if ($uncoveredAdminRoles.Count -gt 0) {
            $evidence += "`nUNCOVERED ADMINISTRATOR ROLES:`n"
            foreach ($role in $uncoveredAdminRoles) {
                $evidence += "  ERROR: $($role.DisplayName) (ID: $($role.Id))`n"
            }
        }
        
        # Perform compliance assessment
        $evidence += "`nCOMPLIANCE ASSESSMENT:`n"
        
        if ($phishingResistantPolicies.Count -gt 0) {
            # Check if ALL admin roles are covered
            if ($uncoveredAdminRoles.Count -eq 0) {
                $controlFinding = "Phishing-resistant MFA strength is enabled for all administrators."
                $controlResult = "COMPLIANT"
                
                $evidence += "SUCCESS: COMPLIANT - All administrator roles are protected by phishing-resistant MFA`n"
                $evidence += "  Phishing-Resistant Policies: $($phishingResistantPolicies.Count)`n"
                $evidence += "  Admin Roles Covered: $($adminRoles.Count)/$($adminRoles.Count)`n"
                $evidence += "  Coverage Percentage: 100%`n"
                $evidence += "  Status: MEETS SECURITY REQUIREMENTS`n"
                
            } else {
                $controlFinding = "Phishing-resistant MFA strength is enabled for some administrators, but not all critical roles are covered."
                $controlResult = "NOT COMPLIANT"
                
                $evidence += "ERROR: NOT COMPLIANT - Some administrator roles lack phishing-resistant MFA protection`n"
                $evidence += "  Phishing-Resistant Policies: $($phishingResistantPolicies.Count)`n"
                $evidence += "  Admin Roles Covered: $($coveredRoleIds.Count)/$($adminRoles.Count)`n"
                $coveragePercentage = [math]::Round(($coveredRoleIds.Count / $adminRoles.Count) * 100, 2)
                $evidence += "  Coverage Percentage: $coveragePercentage%`n"
                $evidence += "  Status: DOES NOT MEET SECURITY REQUIREMENTS`n"
                $evidence += "  Risk: $($uncoveredAdminRoles.Count) administrator roles are vulnerable to phishing attacks`n"
            }
        } else {
            $controlFinding = "No policies with phishing-resistant MFA strength found for administrators."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "ERROR: NOT COMPLIANT - No phishing-resistant MFA policies found`n"
            $evidence += "  Phishing-Resistant Policies: 0`n"
            $evidence += "  Admin Roles Covered: 0/$($adminRoles.Count)`n"
            $evidence += "  Coverage Percentage: 0%`n"
            $evidence += "  Status: CRITICAL SECURITY GAP`n"
            $evidence += "  Risk: All administrator roles are vulnerable to phishing attacks`n"
            
            if ($otherMfaPolicies.Count -gt 0) {
                $evidence += "  Note: $($otherMfaPolicies.Count) policies with other MFA strengths found (not phishing-resistant)`n"
            }
        }
        
        # Security impact analysis
        $evidence += "`nSECURITY IMPACT ANALYSIS:`n"
        if ($controlResult -eq "NOT COMPLIANT") {
            $evidence += "CURRENT RISKS without phishing-resistant MFA for administrators:`n"
            $evidence += "- Administrator accounts vulnerable to phishing attacks`n"
            $evidence += "- Potential for privilege escalation via compromised admin credentials`n"
            $evidence += "- SMS/voice call MFA can be bypassed through SIM swapping`n"
            $evidence += "- Push notification fatigue attacks can compromise accounts`n"
            $evidence += "- Increased risk of tenant-wide compromise`n"
            $evidence += "- Potential for data exfiltration and business disruption`n"
        } else {
            $evidence += "CURRENT PROTECTION with phishing-resistant MFA for administrators:`n"
            $evidence += "+ Administrator accounts protected against phishing attacks`n"
            $evidence += "+ FIDO2 security keys or Windows Hello for Business provide strong authentication`n"
            $evidence += "+ Cryptographic proof of authentication prevents man-in-the-middle attacks`n"
            $evidence += "+ Reduced risk of privilege escalation through compromised credentials`n"
            $evidence += "+ Compliance with zero-trust security principles`n"
        }
        
        # Get affected accounts for non-compliant scenarios
        $affectedAccounts = @()
        if ($controlResult -eq "NOT COMPLIANT") {
            try {
                $evidence += "`nAFFECTED ACCOUNTS ANALYSIS:`n"
                
                # Get users assigned to uncovered admin roles
                foreach ($role in $uncoveredAdminRoles) {
                    try {
                        $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
                        
                        foreach ($assignment in $roleAssignments) {
                            try {
                                $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                if ($user) {
                                    $affectedAccounts += [PSCustomObject]@{
                                        Name = $user.DisplayName
                                        Id = $user.Id
                                        Details = "Administrator role: $($role.DisplayName) - Missing phishing-resistant MFA"
                                    }
                                } else {
                                    $sp = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                    if ($sp) {
                                        $affectedAccounts += [PSCustomObject]@{
                                            Name = $sp.DisplayName
                                            Id = $sp.Id
                                            Details = "Service Principal with admin role: $($role.DisplayName)"
                                        }
                                    }
                                }
                            } catch {
                                # Skip if can't resolve principal
                            }
                        }
                    } catch {
                        $evidence += "  Unable to retrieve assignments for role: $($role.DisplayName)`n"
                    }
                }
                
                $evidence += "Total Affected Accounts: $($affectedAccounts.Count)`n"
                
            } catch {
                $evidence += "Unable to retrieve affected accounts: $_`n"
            }
        }
        
        # Add verification commands
        $evidence += "`nVERIFICATION COMMANDS:`n"
        $evidence += "To manually verify phishing-resistant MFA configuration:`n"
        $evidence += @"
```powershell
# Connect with required permissions
Connect-MgGraph -Scopes 'Policy.Read.All', 'RoleManagement.Read.All'

# Check for phishing-resistant MFA policies
`$policies = Get-MgIdentityConditionalAccessPolicy
`$phishingResistantPolicies = `$policies | Where-Object {
    `$_.GrantControls.AuthenticationStrength.Id -eq '00000000-0000-0000-0000-000000000004'
}
`$phishingResistantPolicies | Select-Object DisplayName, State

# Check administrator role coverage
`$adminRoles = Get-MgRoleManagementDirectoryRoleDefinition | 
    Where-Object { `$_.IsBuiltIn -and `$_.DisplayName -match 'Administrator' }
`$adminRoles | Select-Object DisplayName, Id
```
"@
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<h4>Remediation Steps for Implementing Phishing-Resistant MFA:</h4>

<h5>Phase 1: Prepare Authentication Methods</h5>
<ol>
    <li><strong>Enable FIDO2 Security Keys:</strong>
        <ul>
            <li>Navigate to <strong>Protection > Authentication methods</strong></li>
            <li>Enable <strong>FIDO2 security keys</strong></li>
            <li>Configure target users (administrators)</li>
        </ul>
    </li>
    <li><strong>Enable Windows Hello for Business:</strong>
        <ul>
            <li>Configure Windows Hello for Business for admin devices</li>
            <li>Ensure proper certificate or key trust configuration</li>
        </ul>
    </li>
</ol>

<h5>Phase 2: Create Phishing-Resistant MFA Policy</h5>
<ol>
    <li><strong>Navigate to Conditional Access:</strong>
        <ul>
            <li>Go to <a href="https://entra.microsoft.com" target="_blank">Microsoft Entra admin center</a></li>
            <li>Navigate to <strong>Protection > Conditional Access</strong></li>
        </ul>
    </li>
    <li><strong>Create New Policy:</strong>
        <ul>
            <li>Click <strong>New policy</strong></li>
            <li>Name: "Require Phishing-Resistant MFA for Administrators"</li>
        </ul>
    </li>
    <li><strong>Configure Users and Groups:</strong>
        <ul>
            <li>Include: <strong>Directory roles</strong></li>
            <li>Select all administrator roles</li>
        </ul>
    </li>
    <li><strong>Configure Cloud Apps:</strong>
        <ul>
            <li>Include: <strong>All cloud apps</strong></li>
        </ul>
    </li>
    <li><strong>Configure Grant Controls:</strong>
        <ul>
            <li>Select <strong>Require authentication strength</strong></li>
            <li>Choose <strong>Phishing-resistant MFA</strong></li>
        </ul>
    </li>
    <li><strong>Enable Policy:</strong>
        <ul>
            <li>Set policy to <strong>Report-only</strong> initially</li>
            <li>Monitor for 1-2 weeks</li>
            <li>Change to <strong>On</strong> after validation</li>
        </ul>
    </li>
</ol>

<h4>Verification Commands:</h4>
<pre>
# Verify the policy is working
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy | 
    Where-Object { $_.GrantControls.AuthenticationStrength.Id -eq "00000000-0000-0000-0000-000000000004" } |
    Select-Object DisplayName, State
</pre>
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
        $errorEvidence += "An unexpected error occurred during phishing-resistant MFA assessment.`n`n"
        $errorEvidence += "Error Details:`n"
        $errorEvidence += "- Message: $_`n"
        $errorEvidence += "- Type: $($_.Exception.GetType().Name)`n"
        $errorEvidence += "- Stack Trace: $($_.ScriptStackTrace)`n`n"
        $errorEvidence += "Possible Causes:`n"
        $errorEvidence += "- Insufficient permissions (requires Policy.Read.All, RoleManagement.Read.All)`n"
        $errorEvidence += "- Network connectivity issues`n"
        $errorEvidence += "- Microsoft Graph API service issues`n"
        $errorEvidence += "- Authentication token expiration`n"
        
        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = "Error occurred during phishing-resistant MFA assessment: $_"
            Result = "ERROR"
            Evidence = $errorEvidence
            RemediationSteps = "Resolve the error above and re-run the assessment. Ensure you have Policy.Read.All and RoleManagement.Read.All permissions."
        }
    }
}

# Call the function
Check-AuthenticationStrength