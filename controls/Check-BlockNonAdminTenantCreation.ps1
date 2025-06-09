function Check-BlockNonAdminTenantCreation {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"
        $controlDescription = "Restricting tenant creation prevents unauthorized or uncontrolled deployment of resources and ensures that the organization retains control over its infrastructure. User generation of shadow IT could lead to multiple, disjointed environments that can make it difficult for IT to manage and secure the organization's data, especially if other users in the organization began using these tenants for business purposes under the misunderstanding that they were secured by the organization's security team."
    
        # Build comprehensive evidence collection
        $evidence = "=== TENANT CREATION RESTRICTION ASSESSMENT ===`n"
        $evidence += "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $evidence += "Control: Non-Admin Tenant Creation Restrictions`n"
        $evidence += "CIS Control: Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'`n"
        $evidence += "Assessed By: $($env:USERNAME) on $($env:COMPUTERNAME)`n`n"
        
        # Document the API calls we're making
        $evidence += "MICROSOFT GRAPH API CALLS EXECUTED:`n"
        $evidence += "1. Get-MgPolicyAuthorizationPolicy`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/policies/authorizationPolicy`n"
        $evidence += "   Purpose: Retrieve the authorization policy that controls user permissions`n"
        $evidence += "   Required Permission: Policy.Read.All`n`n"
        
        # Execute the API call and capture detailed information
        $authorizationPolicy = $null
        try {
            $evidence += "API CALL EXECUTION:`n"
            $authorizationPolicy = Get-MgPolicyAuthorizationPolicy
            $evidence += "SUCCESS: Successfully retrieved authorization policy`n"
            $evidence += "  Policy ID: $($authorizationPolicy.Id)`n"
            $evidence += "  Display Name: $($authorizationPolicy.DisplayName)`n"
            $evidence += "  Description: $($authorizationPolicy.Description)`n"
            $evidence += "  Last Modified: $($authorizationPolicy.ModifiedDateTime)`n"
        } catch {
            $evidence += "ERROR: Failed to retrieve authorization policy`n"
            $evidence += "  Error Details: $_`n"
            $evidence += "  This may indicate insufficient permissions or connectivity issues`n"
            
            return [PSCustomObject]@{
                Control = $controlTitle
                ControlDescription = $controlDescription
                Finding = "Unable to assess tenant creation restrictions due to API access error."
                Result = "ERROR"
                Evidence = $evidence
                RemediationSteps = "Ensure you have Policy.Read.All permissions and try again."
            }
        }
        
        $evidence += "`n"
        
        # Extract and analyze the default user role permissions
        $evidence += "DEFAULT USER ROLE PERMISSIONS ANALYSIS:`n"
        $defaultUserRolePermissions = $authorizationPolicy.DefaultUserRolePermissions
        
        if ($defaultUserRolePermissions) {
            $evidence += "SUCCESS: Default user role permissions object found`n"
            
            # Document all the permissions we can see
            $evidence += "  Available Permission Properties:`n"
            $permissionProperties = $defaultUserRolePermissions | Get-Member -MemberType Property | Select-Object -ExpandProperty Name
            foreach ($property in $permissionProperties) {
                $value = $defaultUserRolePermissions.$property
                $evidence += "    - $property`: $value`n"
            }
        } else {
            $evidence += "ERROR: Default user role permissions not found in policy`n"
        }
        
        $evidence += "`n"
        
        # Focus on the specific setting we're checking
        $evidence += "TENANT CREATION PERMISSION ANALYSIS:`n"
        $allowedToCreateTenants = $defaultUserRolePermissions.AllowedToCreateTenants
        
        $evidence += "Setting Name: AllowedToCreateTenants`n"
        $evidence += "Current Value: $allowedToCreateTenants`n"
        $evidence += "Data Type: $($allowedToCreateTenants.GetType().Name)`n"
        
        # Provide detailed interpretation of the setting
        $evidence += "`nSETTING INTERPRETATION:`n"
        $evidence += "Microsoft Documentation Reference:`n"
        $evidence += "- True = Users CAN create new Azure AD tenants (LESS SECURE)`n"
        $evidence += "- False = Users CANNOT create new Azure AD tenants (MORE SECURE)`n"
        $evidence += "- This setting controls whether non-administrator users can create new tenants`n"
        $evidence += "- Admin users (Global Administrator role) can always create tenants regardless of this setting`n"
        
        # Perform the compliance assessment with detailed reasoning
        $evidence += "`nCOMPLIANCE ASSESSMENT:`n"
        
        # Note: The logic here handles the fact that the CIS control says "set to Yes" but that means restricting (False in API)
        if ($allowedToCreateTenants -eq $false) {
            $controlFinding = "Non-admin users are restricted from creating tenants (COMPLIANT)"
            $controlResult = "COMPLIANT"
            
            $evidence += "SUCCESS: COMPLIANT - Tenant creation is properly restricted`n"
            $evidence += "  Current API Value: False (users cannot create tenants)`n"
            $evidence += "  CIS Requirement: 'Restrict non-admin users from creating tenants' should be 'Yes'`n"
            $evidence += "  Status: MEETS REQUIREMENT`n"
            $evidence += "  Security Benefit: Prevents shadow IT and unauthorized resource deployment`n"
            
        } else {
            $controlFinding = "Non-admin users are NOT restricted from creating tenants (NON-COMPLIANT)"
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "ERROR: NON-COMPLIANT - Tenant creation is not restricted`n"
            $evidence += "  Current API Value: True (users CAN create tenants)`n"
            $evidence += "  CIS Requirement: 'Restrict non-admin users from creating tenants' should be 'Yes'`n"
            $evidence += "  Status: DOES NOT MEET REQUIREMENT`n"
            $evidence += "  Security Risk: Users can create unauthorized tenants leading to shadow IT`n"
        }
        
        $evidence += "`n"
        
        # Add impact analysis
        $evidence += "SECURITY IMPACT ANALYSIS:`n"
        if ($controlResult -eq "NOT COMPLIANT") {
            $evidence += "CURRENT RISKS with unrestricted tenant creation:`n"
            $evidence += "- Users can create new Azure AD tenants without IT oversight`n"
            $evidence += "- Potential for shadow IT environments outside corporate governance`n"
            $evidence += "- Data may be stored in unmanaged/unsecured tenants`n"
            $evidence += "- Compliance violations if regulated data ends up in uncontrolled tenants`n"
            $evidence += "- Increased attack surface with multiple, potentially unsecured environments`n"
            $evidence += "- Budget implications from untracked Azure resource consumption`n"
        } else {
            $evidence += "CURRENT PROTECTION with restricted tenant creation:`n"
            $evidence += "+ Only administrators can create new tenants`n"
            $evidence += "+ Prevents unauthorized shadow IT deployments`n"
            $evidence += "+ Maintains centralized control over organizational cloud resources`n"
            $evidence += "+ Ensures new tenants follow organizational security and compliance policies`n"
        }
        
        # Add context about who can still create tenants
        $evidence += "`n"
        $evidence += "ADMINISTRATIVE TENANT CREATION:`n"
        $evidence += "The following roles can always create tenants regardless of this setting:`n"
        $evidence += "- Global Administrator`n"
        $evidence += "- Directory Synchronization Account (for hybrid scenarios)`n"
        $evidence += "These roles maintain the ability to create tenants for legitimate business needs.`n"
        
        # Sample verification commands
        $evidence += "`n"
        $evidence += "VERIFICATION COMMANDS:`n"
        $evidence += "To manually verify this setting using PowerShell:`n"
        $evidence += @"
```powershell
Connect-MgGraph -Scopes 'Policy.Read.All'
`$policy = Get-MgPolicyAuthorizationPolicy
`$policy.DefaultUserRolePermissions.AllowedToCreateTenants
# Should return: False (for compliant configuration)
```
"@
        
        # Get affected accounts if non-compliant
        $affectedAccounts = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            try {
                # Get a sample of standard users who would be affected
                $evidence += "`n`nAFFECTED USERS ANALYSIS:`n"
                $standardUsers = Get-MgUser -Top 50 | Where-Object { 
                    $_.UserType -eq "Member" -and 
                    -not ($_.DisplayName -match "service|admin|system")
                }
                
                $evidence += "Sample of users who can currently create tenants: $($standardUsers.Count) users found`n"
                
                $affectedAccounts = @()
                foreach ($user in $standardUsers | Select-Object -First 10) {
                    $affectedAccounts += [PSCustomObject]@{
                        Name = $user.DisplayName
                        Id = $user.Id
                        Details = "Standard user with tenant creation rights - UPN: $($user.UserPrincipalName)"
                    }
                }
                
                if ($standardUsers.Count -gt 10) {
                    $evidence += "Note: Only showing first 10 affected users in the report. Total affected: $($standardUsers.Count) users`n"
                }
            } catch {
                $evidence += "Unable to retrieve affected users list: $_`n"
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<h4>Immediate Remediation Steps:</h4>
<ol>
    <li><strong>Access Entra Admin Center:</strong>
        <ul>
            <li>Navigate to <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
            <li>Sign in with Global Administrator credentials</li>
        </ul>
    </li>
    <li><strong>Navigate to User Settings:</strong>
        <ul>
            <li>Go to <strong>Identity > Users > User settings</strong></li>
            <li>Scroll down to find the tenant creation settings</li>
        </ul>
    </li>
    <li><strong>Modify Tenant Creation Setting:</strong>
        <ul>
            <li>Find <strong>"Users can create Azure AD tenants"</strong></li>
            <li>Set this to <strong>"No"</strong></li>
            <li>This will set the API value AllowedToCreateTenants to False</li>
        </ul>
    </li>
    <li><strong>Save and Verify:</strong>
        <ul>
            <li>Click <strong>Save</strong> to apply the changes</li>
            <li>Wait a few minutes for the change to propagate</li>
            <li>Verify using the PowerShell commands provided in the evidence</li>
        </ul>
    </li>
</ol>

<h4>Verification After Changes:</h4>
<p>Run this PowerShell command to confirm the change:</p>
<pre>
Connect-MgGraph -Scopes "Policy.Read.All"
(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.AllowedToCreateTenants
# Expected result: False
</pre>

<h4>Business Impact Considerations:</h4>
<ul>
    <li><strong>Positive Impact:</strong> Prevents unauthorized shadow IT and maintains security oversight</li>
    <li><strong>Process Change:</strong> Users who need new tenants must request them through IT/Admin channels</li>
    <li><strong>Exception Handling:</strong> Document a process for legitimate tenant creation requests</li>
</ul>

<h4>Related Security Controls:</h4>
<p>Consider also implementing these related controls:</p>
<ul>
    <li>Azure Policy to control resource creation in existing tenants</li>
    <li>Conditional Access policies for administrative accounts</li>
    <li>Regular reviews of existing tenants and their purpose</li>
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

    } catch {
        $errorEvidence = "=== ASSESSMENT ERROR ===`n"
        $errorEvidence += "An unexpected error occurred during the tenant creation restriction assessment.`n`n"
        $errorEvidence += "Error Details:`n"
        $errorEvidence += "- Message: $_`n"
        $errorEvidence += "- Type: $($_.Exception.GetType().Name)`n"
        $errorEvidence += "- Stack Trace: $($_.ScriptStackTrace)`n`n"
        $errorEvidence += "Possible Causes:`n"
        $errorEvidence += "- Insufficient permissions (requires Policy.Read.All)`n"
        $errorEvidence += "- Network connectivity issues`n"
        $errorEvidence += "- Microsoft Graph API service issues`n"
        $errorEvidence += "- Authentication token expiration`n"
        
        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = "Error occurred during assessment: $_"
            Result = "ERROR"
            Evidence = $errorEvidence
            RemediationSteps = "Resolve the error above and re-run the assessment. Ensure you have appropriate Microsoft Graph permissions."
        }
    }
}

# Call the function
Check-BlockNonAdminTenantCreation