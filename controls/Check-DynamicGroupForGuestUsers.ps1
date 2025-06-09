function Check-DynamicGroupForGuestUsers {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure a dynamic group for guest users is created"
        $controlDescription = "A dynamic group is a dynamic configuration of security group membership for Azure Active Directory. Administrators can set rules to populate groups that are created in Azure AD based on user attributes (such as userType, department, or country/region). Members can be automatically added to or removed from a security group based on their attributes. The recommended state is to create a dynamic group that includes guest accounts."

        # Build comprehensive evidence collection
        $evidence = "=== DYNAMIC GROUP FOR GUEST USERS ASSESSMENT ===`n"
        $evidence += "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $evidence += "Control: Dynamic Group Configuration for Guest Users`n"
        $evidence += "CIS Control: Ensure a dynamic group for guest users is created`n"
        $evidence += "Assessed By: $($env:USERNAME) on $($env:COMPUTERNAME)`n`n"
        
        # Document Microsoft Graph API calls
        $evidence += "MICROSOFT GRAPH API CALLS EXECUTED:`n"
        $evidence += "1. Get-MgGroup (with GroupTypes filter)`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/groups`n"
        $evidence += "   Purpose: Retrieve all groups and identify dynamic membership groups`n"
        $evidence += "   Required Permission: Group.Read.All`n`n"
        
        $evidence += "2. Get-MgUser (with UserType filter)`n"
        $evidence += "   Endpoint: https://graph.microsoft.com/v1.0/users`n"
        $evidence += "   Purpose: Identify current guest users in the tenant`n"
        $evidence += "   Required Permission: User.Read.All`n`n"
        
        # Get all groups with dynamic membership
        $groups = $null
        try {
            $evidence += "API CALL 1 EXECUTION - Groups Analysis:`n"
            $groups = Get-MgGroup | Where-Object { $_.GroupTypes -contains "DynamicMembership" }
            $evidence += "SUCCESS: Successfully retrieved group information`n"
            
            # Get total groups for context
            $allGroups = Get-MgGroup
            $evidence += "  Total Groups in Tenant: $($allGroups.Count)`n"
            $evidence += "  Dynamic Membership Groups: $($groups.Count)`n"
            
            if ($groups.Count -gt 0) {
                $evidence += "  Dynamic Groups Found:`n"
                foreach ($group in $groups) {
                    $evidence += "    - $($group.DisplayName) (ID: $($group.Id))`n"
                    $evidence += "      Membership Rule: $($group.MembershipRule)`n"
                    $evidence += "      Processing State: $($group.MembershipRuleProcessingState)`n"
                }
            } else {
                $evidence += "  No dynamic membership groups found in tenant`n"
            }
            
        } catch {
            $evidence += "ERROR: Failed to retrieve group information`n"
            $evidence += "  Error Details: $_`n"
            
            return [PSCustomObject]@{
                Control = $controlTitle
                ControlDescription = $controlDescription
                Finding = "Unable to assess dynamic groups due to API access error."
                Result = "ERROR"
                Evidence = $evidence
                RemediationSteps = "Ensure you have Group.Read.All permissions and try again."
            }
        }
        
        # Get current guest users for context
        $guestUsers = $null
        $totalGuestUsers = 0
        try {
            $evidence += "`nAPI CALL 2 EXECUTION - Guest Users Analysis:`n"
            $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Top 20 -Property DisplayName, UserPrincipalName, CreatedDateTime, UserType
            
            # Try to get total count
            try {
                $allGuestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Count -ConsistencyLevel eventual
                $totalGuestUsers = $allGuestUsers.Count
            } catch {
                $totalGuestUsers = $guestUsers.Count
            }
            
            $evidence += "SUCCESS: Successfully retrieved guest user information`n"
            $evidence += "  Total Guest Users in Tenant: $totalGuestUsers`n"
            $evidence += "  Sample Guest Users Retrieved: $($guestUsers.Count)`n"
            
            if ($guestUsers.Count -gt 0) {
                $evidence += "  Recent Guest Users (sample):`n"
                foreach ($guest in $guestUsers | Select-Object -First 5) {
                    $evidence += "    - $($guest.DisplayName) ($($guest.UserPrincipalName))`n"
                    $evidence += "      Created: $($guest.CreatedDateTime)`n"
                }
                
                if ($guestUsers.Count -gt 5) {
                    $evidence += "    ... and $($guestUsers.Count - 5) more guest users`n"
                }
            } else {
                $evidence += "  No guest users found in tenant`n"
            }
            
        } catch {
            $evidence += "ERROR: Failed to retrieve guest user information`n"
            $evidence += "  Error Details: $_`n"
            $evidence += "  Impact: Cannot assess guest user population for dynamic group needs`n"
            # Continue assessment without guest user context
        }
        
        $evidence += "`n"
        
        # Analyze dynamic groups for guest user patterns
        $evidence += "DYNAMIC GROUP MEMBERSHIP RULE ANALYSIS:`n"
        $evidence += "Target Rule Patterns for Guest Users:`n"
        $evidence += "  - user.userType -eq `"Guest`"`n"
        $evidence += "  - (user.userType -eq `"Guest`")`n"
        $evidence += "  - user.userType -contains `"Guest`"`n`n"
        
        # Filter dynamic groups for guest users
        $guestDynamicGroups = @()
        $otherDynamicGroups = @()
        
        if ($groups -and $groups.Count -gt 0) {
            foreach ($group in $groups) {
                $rule = $group.MembershipRule
                $evidence += "Analyzing Group: $($group.DisplayName)`n"
                $evidence += "  Membership Rule: $rule`n"
                
                if ($rule -like "*user.userType*-eq*`"Guest`"*" -or $rule -like "*user.userType*eq*'Guest'*") {
                    $guestDynamicGroups += $group
                    $evidence += "  SUCCESS: GUEST USER DYNAMIC GROUP DETECTED`n"
                    
                    # Check group membership count if available
                    try {
                        $members = Get-MgGroupMember -GroupId $group.Id -Top 1
                        $memberCount = (Get-MgGroupMember -GroupId $group.Id -Count -ConsistencyLevel eventual).Count
                        $evidence += "  Current Members: $memberCount`n"
                    } catch {
                        $evidence += "  Current Members: Unable to retrieve count`n"
                    }
                    
                } elseif ($rule -like "*user.userType*-eq*`"Member`"*" -or $rule -like "*user.userType*eq*'Member'*") {
                    $evidence += "  INFO: Member users dynamic group`n"
                    $otherDynamicGroups += $group
                } elseif ($rule -match "user\.userType") {
                    $evidence += "  INFO: Other userType-based dynamic group`n"
                    $otherDynamicGroups += $group
                } else {
                    $evidence += "  INFO: Other dynamic group (not userType-based)`n"
                    $otherDynamicGroups += $group
                }
                
                $evidence += "`n"
            }
        } else {
            $evidence += "No dynamic groups found to analyze`n"
        }
        
        # Perform compliance assessment
        $evidence += "COMPLIANCE ASSESSMENT:`n"
        
        if ($guestDynamicGroups.Count -gt 0) {
            $controlFinding = "Dynamic group for guest users found."
            $controlResult = "COMPLIANT"
            
            $evidence += "SUCCESS: COMPLIANT - Dynamic group(s) for guest users are configured`n"
            $evidence += "  Guest Dynamic Groups Found: $($guestDynamicGroups.Count)`n"
            $evidence += "  Status: MEETS REQUIREMENT`n"
            
            foreach ($group in $guestDynamicGroups) {
                $evidence += "  Group Details:`n"
                $evidence += "    - Name: $($group.DisplayName)`n"
                $evidence += "    - Rule: $($group.MembershipRule)`n"
                $evidence += "    - Processing State: $($group.MembershipRuleProcessingState)`n"
                $evidence += "    - Created: $($group.CreatedDateTime)`n"
            }
            
            $evidence += "  Security Benefits:`n"
            $evidence += "    + Automatic guest user management and organization`n"
            $evidence += "    + Consistent application of policies to all guest users`n"
            $evidence += "    + Simplified access reviews and governance`n"
            $evidence += "    + Automated group membership based on user type`n"
            
        } else {
            $controlFinding = "No dynamic group for guest users found."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "ERROR: NOT COMPLIANT - No dynamic groups for guest users detected`n"
            $evidence += "  Guest Dynamic Groups Found: 0`n"
            $evidence += "  Total Dynamic Groups: $($groups.Count)`n"
            $evidence += "  Status: DOES NOT MEET REQUIREMENT`n"
            
            if ($totalGuestUsers -gt 0) {
                $evidence += "  Impact: $totalGuestUsers guest users are not automatically grouped`n"
                $evidence += "  Risk: Manual guest user management required`n"
                $evidence += "  Consequence: Difficult to apply consistent policies to guest users`n"
            } else {
                $evidence += "  Current Guest Users: 0 (no immediate impact)`n"
                $evidence += "  Future Risk: Guest users added later will not be automatically grouped`n"
            }
            
            if ($groups.Count -gt 0) {
                $evidence += "`n  Existing Dynamic Groups (not for guests):`n"
                foreach ($group in $otherDynamicGroups | Select-Object -First 3) {
                    $evidence += "    - $($group.DisplayName): $($group.MembershipRule)`n"
                }
                if ($otherDynamicGroups.Count -gt 3) {
                    $evidence += "    ... and $($otherDynamicGroups.Count - 3) more dynamic groups`n"
                }
            }
        }
        
        # Security impact analysis
        $evidence += "`nSECURITY IMPACT ANALYSIS:`n"
        if ($controlResult -eq "NOT COMPLIANT") {
            $evidence += "CURRENT RISKS without dynamic guest user groups:`n"
            $evidence += "- Manual tracking and management of guest users required`n"
            $evidence += "- Inconsistent policy application to guest accounts`n"
            $evidence += "- Difficult to perform bulk operations on guest users`n"
            $evidence += "- Challenging to implement guest-specific Conditional Access policies`n"
            $evidence += "- Manual effort required for access reviews and governance`n"
            $evidence += "- Risk of overlooking guest accounts in security assessments`n"
            $evidence += "- Scalability issues as guest user population grows`n"
        } else {
            $evidence += "CURRENT PROTECTION with dynamic guest user groups:`n"
            $evidence += "+ Automatic organization and management of guest users`n"
            $evidence += "+ Consistent policy application across all guest accounts`n"
            $evidence += "+ Simplified bulk operations and access reviews`n"
            $evidence += "+ Enhanced governance and compliance tracking`n"
            $evidence += "+ Improved security monitoring and reporting`n"
            $evidence += "+ Scalable guest user management as population grows`n"
        }
        
        # Affected accounts analysis for non-compliant scenarios
        $affectedAccounts = @()
        if ($controlResult -eq "NOT COMPLIANT" -and $guestUsers.Count -gt 0) {
            $evidence += "`nAFFECTED GUEST ACCOUNTS:`n"
            $evidence += "Guest users not automatically grouped: $totalGuestUsers`n"
            
            foreach ($guest in $guestUsers | Select-Object -First 20) {
                $affectedAccounts += [PSCustomObject]@{
                    Name = $guest.DisplayName
                    Id = $guest.Id
                    Details = "Guest user not in dynamic group - UPN: $($guest.UserPrincipalName)"
                }
            }
            
            if ($totalGuestUsers -gt 20) {
                $evidence += "Note: Showing first 20 affected accounts. Total affected: $totalGuestUsers guests`n"
            }
        }
        
        # Add recommended dynamic group rules
        $evidence += "`nRECOMMENDED DYNAMIC GROUP RULES:`n"
        $evidence += "For Guest Users Only:`n"
        $evidence += "  Rule: user.userType -eq `"Guest`"`n"
        $evidence += "  Description: Includes all guest users (external users invited to collaborate)`n`n"
        
        $evidence += "For All Internal Users:`n"
        $evidence += "  Rule: user.userType -eq `"Member`"`n"
        $evidence += "  Description: Includes all member users (internal organizational users)`n`n"
        
        $evidence += "For Mixed Scenarios:`n"
        $evidence += "  Rule: (user.userType -eq `"Guest`") and (user.department -eq `"Sales`")`n"
        $evidence += "  Description: Example of combining userType with other attributes`n"
        
        # Add verification commands
        $evidence += "`nVERIFICATION COMMANDS:`n"
        $evidence += "To manually verify dynamic group configuration:`n"
        $evidence += @"
```powershell
# Connect with required permissions
Connect-MgGraph -Scopes 'Group.Read.All', 'User.Read.All'

# Check for dynamic groups
`$dynamicGroups = Get-MgGroup | Where-Object { `$_.GroupTypes -contains 'DynamicMembership' }
`$dynamicGroups | Select-Object DisplayName, MembershipRule

# Check for guest user dynamic groups specifically
`$guestGroups = `$dynamicGroups | Where-Object { `$_.MembershipRule -like '*Guest*' }
`$guestGroups | Select-Object DisplayName, MembershipRule, MembershipRuleProcessingState

# Check current guest users
Get-MgUser -Filter "userType eq 'Guest'" | Select-Object DisplayName, UserPrincipalName
```
"@
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<h4>Remediation Steps for Creating Dynamic Guest User Group:</h4>

<h5>Method 1: Using Microsoft Entra Admin Center (Recommended)</h5>
<ol>
    <li><strong>Navigate to Groups Management:</strong>
        <ul>
            <li>Go to <a href="https://entra.microsoft.com" target="_blank">Microsoft Entra admin center</a></li>
            <li>Navigate to <strong>Identity > Groups > All groups</strong></li>
        </ul>
    </li>
    <li><strong>Create New Dynamic Group:</strong>
        <ul>
            <li>Click <strong>New group</strong></li>
            <li>Set <strong>Group type</strong> to <strong>Security</strong></li>
            <li>Enter <strong>Group name</strong>: "All Guest Users" (or similar descriptive name)</li>
            <li>Enter <strong>Group description</strong>: "Dynamic group containing all guest users"</li>
            <li>Set <strong>Membership type</strong> to <strong>Dynamic User</strong></li>
        </ul>
    </li>
    <li><strong>Configure Dynamic Rule:</strong>
        <ul>
            <li>Click <strong>Add dynamic query</strong></li>
            <li>Set the rule to: <code>user.userType -eq "Guest"</code></li>
            <li>Click <strong>Validate Rules</strong> to test the query</li>
            <li>Verify that existing guest users are found by the rule</li>
        </ul>
    </li>
    <li><strong>Finalize Group Creation:</strong>
        <ul>
            <li>Review all settings</li>
            <li>Click <strong>Create</strong></li>
            <li>Wait for initial membership processing (may take several minutes)</li>
        </ul>
    </li>
</ol>

<h5>Method 2: Using PowerShell</h5>
<pre>
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Group.ReadWrite.All"

# Create the dynamic group
New-MgGroup -DisplayName "All Guest Users" -Description "Dynamic group containing all guest users" -GroupTypes @("DynamicMembership") -SecurityEnabled -MailEnabled:`$false -MembershipRule 'user.userType -eq "Guest"' -MembershipRuleProcessingState "On"
</pre>

<h4>Monitoring and Maintenance:</h4>
<ul>
    <li>Regularly review group membership accuracy</li>
    <li>Monitor dynamic rule processing status</li>
    <li>Update rules as business requirements change</li>
    <li>Document the group purpose and usage for other administrators</li>
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
        $errorEvidence += "An unexpected error occurred during dynamic group assessment.`n`n"
        $errorEvidence += "Error Details:`n"
        $errorEvidence += "- Message: $_`n"
        $errorEvidence += "- Type: $($_.Exception.GetType().Name)`n"
        $errorEvidence += "- Stack Trace: $($_.ScriptStackTrace)`n`n"
        $errorEvidence += "Possible Causes:`n"
        $errorEvidence += "- Insufficient permissions (requires Group.Read.All, User.Read.All)`n"
        $errorEvidence += "- Network connectivity issues`n"
        $errorEvidence += "- Microsoft Graph API service issues`n"
        $errorEvidence += "- Authentication token expiration`n"
        
        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = "Error occurred during dynamic group assessment: $_"
            Result = "ERROR"
            Evidence = $errorEvidence
            RemediationSteps = "Resolve the error above and re-run the assessment. Ensure you have Group.Read.All and User.Read.All permissions."
        }
    }
}

# Call the function
Check-DynamicGroupForGuestUsers