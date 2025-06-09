function Check-SecurityDefaultStatus {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure Security Defaults is disabled on Azure Active Directory"
        $controlDescription = "Security defaults provide secure default settings that are managed on behalf of organizations to keep customers safe until they are ready to manage their own identity security settings. For example, doing the following: Requiring all users and admins to register for MFA. Challenging users with MFA - mostly when they show up on a new device or app, but more often for critical roles and tasks. Disabling authentication from legacy authentication clients, which can't do MFA."

        # Build comprehensive evidence collection
        $evidence = "=== SECURITY DEFAULTS ASSESSMENT EVIDENCE ===`n"
        $evidence += "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $evidence += "Control: Security Defaults Configuration`n"
        $evidence += "CIS Control: Ensure Security Defaults is disabled on Azure Active Directory`n"
        $evidence += "Assessed By: $($env:USERNAME) on $($env:COMPUTERNAME)`n`n"
        
        # Document the Microsoft Graph API calls
        $evidence += "MICROSOFT GRAPH API CALLS EXECUTED:`n"
        $evidence += "1. Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy`n"
        $evidence += "   Purpose: Retrieve the current state of Security Defaults enforcement`n"
        $evidence += "   Required Permission: Policy.Read.All`n`n"
        
        $evidence += "2. Get-MgIdentityConditionalAccessPolicy`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`n"
        $evidence += "   Purpose: Check for alternative Conditional Access policies`n"
        $evidence += "   Required Permission: Policy.Read.All`n`n"
        
        # Execute Security Defaults check
        $securityDefaultsPolicy = $null
        try {
            $evidence += "API CALL 1 EXECUTION - Security Defaults Policy:`n"
            $securityDefaultsPolicy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
            $evidence += "SUCCESS: Successfully retrieved Security Defaults policy`n"
            $evidence += "  Policy ID: $($securityDefaultsPolicy.Id)`n"
            $evidence += "  Display Name: $($securityDefaultsPolicy.DisplayName)`n"
            $evidence += "  Description: $($securityDefaultsPolicy.Description)`n"
            $evidence += "  IsEnabled: $($securityDefaultsPolicy.IsEnabled)`n"
            $evidence += "  Last Modified: $($securityDefaultsPolicy.ModifiedDateTime)`n"
        } catch {
            $evidence += "ERROR: Failed to retrieve Security Defaults policy`n"
            $evidence += "  Error Details: $_`n"
            
            return [PSCustomObject]@{
                Control = $controlTitle
                ControlDescription = $controlDescription
                Finding = "Unable to assess Security Defaults due to API access error."
                Result = "ERROR"
                Evidence = $evidence
                RemediationSteps = "Ensure you have Policy.Read.All permissions and try again."
            }
        }
        
        # Execute Conditional Access policies check
        $conditionalAccessPolicies = $null
        try {
            $evidence += "`nAPI CALL 2 EXECUTION - Conditional Access Policies:`n"
            $conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy
            $evidence += "SUCCESS: Successfully retrieved Conditional Access policies`n"
            $evidence += "  Total Policies Found: $($conditionalAccessPolicies.Count)`n"
            
            # Analyze policy states
            $enabledPolicies = $conditionalAccessPolicies | Where-Object { $_.State -eq "enabled" }
            $disabledPolicies = $conditionalAccessPolicies | Where-Object { $_.State -eq "disabled" }
            $reportOnlyPolicies = $conditionalAccessPolicies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
            
            $evidence += "  Enabled Policies: $($enabledPolicies.Count)`n"
            $evidence += "  Disabled Policies: $($disabledPolicies.Count)`n"
            $evidence += "  Report-Only Policies: $($reportOnlyPolicies.Count)`n"
            
        } catch {
            $evidence += "`nERROR: Failed to retrieve Conditional Access policies`n"
            $evidence += "  Error Details: $_`n"
            $evidence += "  Impact: Cannot assess alternative security controls`n"
            # Continue assessment without CA policy analysis
        }
        
        $evidence += "`n"
        
        # Analyze Security Defaults configuration
        $evidence += "SECURITY DEFAULTS CONFIGURATION ANALYSIS:`n"
        $securityDefaultsEnabled = $securityDefaultsPolicy.IsEnabled
        
        $evidence += "Setting Name: IsEnabled`n"
        $evidence += "Current Value: $securityDefaultsEnabled`n"
        $evidence += "Data Type: $($securityDefaultsEnabled.GetType().Name)`n"
        $evidence += "Policy Object ID: $($securityDefaultsPolicy.Id)`n"
        
        # Provide detailed interpretation
        $evidence += "`nSETTING INTERPRETATION:`n"
        $evidence += "Microsoft Documentation Reference:`n"
        $evidence += "- True = Security Defaults are ENABLED (basic protection active)`n"
        $evidence += "- False = Security Defaults are DISABLED (custom policies expected)`n"
        $evidence += "`nSecurity Defaults provide:`n"
        $evidence += "- Automatic MFA registration for all users`n"
        $evidence += "- MFA challenges for administrative actions`n"
        $evidence += "- Legacy authentication protocol blocking`n"
        $evidence += "- Azure portal access protection for administrators`n"
        
        # Analyze Conditional Access as alternative protection
        $evidence += "`nCONDITIONAL ACCESS POLICY ANALYSIS:`n"
        if ($conditionalAccessPolicies) {
            $evidence += "Alternative Protection Assessment:`n"
            $evidence += "Total CA Policies: $($conditionalAccessPolicies.Count)`n"
            $evidence += "Active CA Policies: $($enabledPolicies.Count)`n"
            
            if ($enabledPolicies.Count -gt 0) {
                $evidence += "`nActive Policy Summary (first 5):`n"
                foreach ($policy in $enabledPolicies | Select-Object -First 5) {
                    $evidence += "- Policy: $($policy.DisplayName)`n"
                    $evidence += "  State: $($policy.State)`n"
                    $evidence += "  Created: $($policy.CreatedDateTime)`n"
                    $evidence += "  Modified: $($policy.ModifiedDateTime)`n"
                }
                
                if ($enabledPolicies.Count -gt 5) {
                    $evidence += "... and $($enabledPolicies.Count - 5) more active policies`n"
                }
            }
        } else {
            $evidence += "Unable to assess Conditional Access policies due to API access limitations`n"
        }
        
        # Perform compliance assessment with detailed reasoning
        $evidence += "`nCOMPLIANCE ASSESSMENT:`n"
        
        if ($securityDefaultsEnabled -eq $true) {
            $controlFinding = "Security Defaults are enabled (NON-COMPLIANT per CIS guidance)"
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "ERROR: NON-COMPLIANT - Security Defaults are currently enabled`n"
            $evidence += "  Current Setting: True (Security Defaults active)`n"
            $evidence += "  CIS Requirement: Security Defaults should be disabled`n"
            $evidence += "  Status: DOES NOT MEET CIS REQUIREMENT`n"
            $evidence += "  Reasoning: CIS recommends custom Conditional Access policies over Security Defaults`n"
            
            # Check if there are conflicting CA policies
            if ($conditionalAccessPolicies -and $conditionalAccessPolicies.Count -gt 0) {
                $evidence += "`n  CONFIGURATION CONFLICT DETECTED:`n"
                $evidence += "  - Security Defaults: ENABLED`n"
                $evidence += "  - Conditional Access Policies: $($conditionalAccessPolicies.Count) found`n"
                $evidence += "  - Impact: CA policies may not function as expected when Security Defaults are enabled`n"
                $evidence += "  - Recommendation: Disable Security Defaults and rely on CA policies for control`n"
            }
            
        } else {
            # Security Defaults are disabled - check if adequate alternatives exist
            if ($conditionalAccessPolicies -and $enabledPolicies.Count -ge 3) {
                $controlFinding = "Security Defaults are disabled and replaced with Conditional Access policies (COMPLIANT)"
                $controlResult = "COMPLIANT"
                
                $evidence += "SUCCESS: COMPLIANT - Security Defaults properly disabled with CA alternatives`n"
                $evidence += "  Current Setting: False (Security Defaults disabled)`n"
                $evidence += "  CIS Requirement: Security Defaults should be disabled`n"
                $evidence += "  Status: MEETS CIS REQUIREMENT`n"
                $evidence += "  Alternative Protection: $($enabledPolicies.Count) active Conditional Access policies`n"
                $evidence += "  Assessment: Adequate alternative security controls in place`n"
                
            } elseif ($conditionalAccessPolicies -and $enabledPolicies.Count -gt 0) {
                $controlFinding = "Security Defaults are disabled but may lack adequate Conditional Access replacements"
                $controlResult = "PARTIALLY COMPLIANT"
                
                $evidence += "WARNING: PARTIALLY COMPLIANT - Security Defaults disabled but limited CA policies`n"
                $evidence += "  Current Setting: False (Security Defaults disabled)`n"
                $evidence += "  CIS Requirement: Security Defaults should be disabled (PASS)`n"
                $evidence += "  Alternative Protection: Only $($enabledPolicies.Count) active Conditional Access policies`n"
                $evidence += "  Concern: May not provide equivalent protection to Security Defaults`n"
                $evidence += "  Recommendation: Implement comprehensive CA policies before disabling Security Defaults`n"
                
            } else {
                $controlFinding = "Security Defaults are disabled but no adequate alternatives detected"
                $controlResult = "NOT COMPLIANT"
                
                $evidence += "ERROR: NON-COMPLIANT - Security Defaults disabled without adequate replacements`n"
                $evidence += "  Current Setting: False (Security Defaults disabled)`n"
                $evidence += "  CIS Requirement: Security Defaults should be disabled (PASS)`n"
                $evidence += "  Alternative Protection: No adequate Conditional Access policies detected`n"
                $evidence += "  Security Risk: Tenant may lack basic security protections`n"
                $evidence += "  Recommendation: Implement baseline CA policies or temporarily re-enable Security Defaults`n"
            }
        }
        
        # Security impact analysis
        $evidence += "`nSECURITY IMPACT ANALYSIS:`n"
        if ($securityDefaultsEnabled -eq $true) {
            $evidence += "CURRENT STATE with Security Defaults ENABLED:`n"
            $evidence += "+ Basic MFA protection active for all users`n"
            $evidence += "+ Legacy authentication protocols blocked`n"
            $evidence += "+ Administrator accounts have enhanced protection`n"
            $evidence += "+ Zero-configuration security baseline`n"
            $evidence += "- Limited customization options`n"
            $evidence += "- May conflict with custom Conditional Access policies`n"
            $evidence += "- Less granular control over security requirements`n"
        } else {
            $evidence += "CURRENT STATE with Security Defaults DISABLED:`n"
            $evidence += "+ Full control over authentication policies`n"
            $evidence += "+ Conditional Access policies can be customized`n"
            $evidence += "+ Granular control over security requirements`n"
            if ($enabledPolicies -and $enabledPolicies.Count -ge 3) {
                $evidence += "+ Alternative security controls appear to be in place`n"
            } else {
                $evidence += "- Risk: May lack adequate baseline security protections`n"
                $evidence += "- Requires manual configuration of security policies`n"
            }
        }
        
        # Add verification commands
        $evidence += "`nVERIFICATION COMMANDS:`n"
        $evidence += "To manually verify Security Defaults status:`n"
        $evidence += @"
```powershell
# Connect with required permissions
Connect-MgGraph -Scopes 'Policy.Read.All'

# Check Security Defaults status
`$secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
`$secDefaults.IsEnabled
# Should return: False (for CIS compliance)

# Check Conditional Access policies as alternatives
`$caPolicies = Get-MgIdentityConditionalAccessPolicy
`$caPolicies | Where-Object {`$_.State -eq 'enabled'} | Select-Object DisplayName, State
```
"@
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT" -or $controlResult -eq "PARTIALLY COMPLIANT") {
            if ($securityDefaultsEnabled -eq $true) {
                $remediationSteps = @"
<h4>Remediation Steps for Disabling Security Defaults:</h4>
<div style="background-color: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0;">
<strong>WARNING:</strong> Do not disable Security Defaults until you have implemented adequate Conditional Access policies to replace the protection they provide.
</div>

<h5>Phase 1: Create Baseline Conditional Access Policies</h5>
<ol>
    <li><strong>Create MFA Policy for All Users:</strong>
        <ul>
            <li>Navigate to <strong>Protection > Conditional Access</strong></li>
            <li>Create policy: "Require MFA for All Users"</li>
            <li>Users: All users</li>
            <li>Cloud apps: All cloud apps</li>
            <li>Grant: Require multi-factor authentication</li>
        </ul>
    </li>
    <li><strong>Create Admin MFA Policy:</strong>
        <ul>
            <li>Create policy: "Require MFA for Administrators"</li>
            <li>Users: Directory roles (all admin roles)</li>
            <li>Cloud apps: All cloud apps</li>
            <li>Grant: Require multi-factor authentication</li>
        </ul>
    </li>
    <li><strong>Block Legacy Authentication:</strong>
        <ul>
            <li>Create policy: "Block Legacy Authentication"</li>
            <li>Users: All users</li>
            <li>Cloud apps: All cloud apps</li>
            <li>Conditions: Client apps (Exchange ActiveSync, Other clients)</li>
            <li>Grant: Block access</li>
        </ul>
    </li>
</ol>

<h5>Phase 2: Test Policies</h5>
<ol>
    <li>Set all policies to <strong>"Report-only"</strong> mode first</li>
    <li>Monitor sign-in logs for 1-2 weeks</li>
    <li>Adjust policies based on findings</li>
    <li>Enable policies one by one</li>
</ol>

<h5>Phase 3: Disable Security Defaults</h5>
<ol>
    <li>Navigate to <a href="https://entra.microsoft.com" target="_blank">Microsoft Entra admin center</a></li>
    <li>Go to <strong>Identity > Overview > Properties</strong></li>
    <li>Click <strong>Manage security defaults</strong></li>
    <li>Set <strong>Enable security defaults</strong> to <strong>No</strong></li>
    <li>Select reason: <strong>My organization is using Conditional Access</strong></li>
    <li>Click <strong>Save</strong></li>
</ol>

<h4>Verification After Changes:</h4>
<pre>
Connect-MgGraph -Scopes "Policy.Read.All"
(Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy).IsEnabled
# Expected result: False

# Verify CA policies are active
Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.State -eq "enabled"} | 
    Select-Object DisplayName, State | Format-Table
</pre>
"@
            } else {
                $remediationSteps = @"
<h4>Remediation Steps for Implementing Adequate Security Controls:</h4>
<p>Security Defaults are disabled but adequate Conditional Access policies are not detected. You need to implement baseline security policies:</p>

<ol>
    <li><strong>Implement Baseline MFA Policy:</strong>
        <ul>
            <li>Navigate to <strong>Protection > Conditional Access</strong></li>
            <li>Create comprehensive MFA policies for users and administrators</li>
        </ul>
    </li>
    <li><strong>Block Legacy Authentication:</strong>
        <ul>
            <li>Create policies to block legacy authentication protocols</li>
        </ul>
    </li>
    <li><strong>Consider Temporarily Re-enabling Security Defaults:</strong>
        <ul>
            <li>If you cannot implement CA policies immediately</li>
            <li>Security Defaults provide better protection than no policies</li>
        </ul>
    </li>
</ol>
"@
            }
        }

        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = $controlFinding
            Result = $controlResult
            Evidence = $evidence
            RemediationSteps = $remediationSteps
        }

    } catch {
        $errorEvidence = "=== ASSESSMENT ERROR ===`n"
        $errorEvidence += "An unexpected error occurred during Security Defaults assessment.`n`n"
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
            Finding = "Error occurred during Security Defaults assessment: $_"
            Result = "ERROR"
            Evidence = $errorEvidence
            RemediationSteps = "Resolve the error above and re-run the assessment. Ensure you have Policy.Read.All permissions."
        }
    }
}

# Call the function
Check-SecurityDefaultStatus