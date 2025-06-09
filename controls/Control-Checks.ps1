# Helper function to check for Entra ID P2 license
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
            return $false
        }
        # If it's some other error, we'll consider it might be transient and not license-related
        return $true
    }
}

# Control Check Functions for Entra ID Security Assessment

function Check-AuthenticationStrength {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure 'Phishing-resistant MFA strength' is required for Administrators"
        $controlDescription = "Authentication strength is a Conditional Access control that allows administrators to specify which combination of authentication methods can be used to access a resource. For example, they can make only phishing-resistant authentication methods available to access a sensitive resource. But to access a non-sensitive resource, they can allow less secure multifactor authentication (MFA) combinations, such as password + SMS. Microsoft has 3 built-in authentication strengths. MFA strength, Passwordless MFA strength, and Phishing-resistant MFA strength. Ensure administrator roles are using a CA policy with Phishing-resistant MFA strength."

        # Retrieve all Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy | Sort-Object DisplayName
        
        # Get all administrator roles for reference
        $adminRoles = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { 
            $_.IsBuiltIn -eq $true -and $_.DisplayName -match "Administrator"
        } | Select-Object DisplayName, Id
        
        $evidence = "Administrator roles requiring phishing-resistant MFA protection:`n"
        $phishingResistantPolicies = @()
        
        foreach ($policy in $policies) {
            $policyDetails = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
            $authenticationStrength = $policy.GrantControls.AuthenticationStrength
            
            # Check if policy is for administrators and uses phishing-resistant MFA
            if ($authenticationStrength.id -eq "00000000-0000-0000-0000-000000000004") {
                $phishingResistantPolicies += $policy
                
                $evidence += "`n- Policy Name: $($policy.DisplayName)"
                $evidence += "`n  State: $($policy.State)"
                $evidence += "`n  Authentication Strength: Phishing-resistant MFA"
                
                # Check if policy applies to admin roles
                if ($policyDetails.Conditions.Users.IncludeRoles) {
                    $evidence += "`n  Applied to roles:"
                    foreach ($roleId in $policyDetails.Conditions.Users.IncludeRoles) {
                        $roleName = ($adminRoles | Where-Object { $_.Id -eq $roleId }).DisplayName
                        $evidence += "`n    - $roleName"
                    }
                }
                
                $evidence += "`n"
            }
        }

        # Get admin roles NOT covered by phishing-resistant MFA policies
        $coveredRoleIds = @()
        foreach ($policy in $phishingResistantPolicies) {
            $policyDetails = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
            if ($policyDetails.Conditions.Users.IncludeRoles) {
                $coveredRoleIds += $policyDetails.Conditions.Users.IncludeRoles
            }
        }
        
        $uncoveredAdminRoles = $adminRoles | Where-Object { $coveredRoleIds -notcontains $_.Id }
        
        if ($phishingResistantPolicies.Count -gt 0) {
            # Check if ALL admin roles are covered
            if ($uncoveredAdminRoles.Count -eq 0) {
                $controlFinding = "Phishing-resistant MFA strength is enabled for all administrators."
                $controlResult = "COMPLIANT"
            } else {
                $controlFinding = "Phishing-resistant MFA strength is enabled for some administrators, but not all critical roles are covered."
                $controlResult = "NOT COMPLIANT"
                
                $evidence += "`nAdmin roles NOT protected by phishing-resistant MFA policies:`n"
                foreach ($role in $uncoveredAdminRoles) {
                    $evidence += "`n- $($role.DisplayName)"
                }

                # Note: The affected accounts section is modified to not use PIM-specific APIs
                $affectedAccounts = @()
                foreach ($role in $uncoveredAdminRoles) {
                    try {
                        # Use regular role assignments instead of PIM assignments
                        $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $role.Id
                        if ($roleDefinition) {
                            $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
                            
                            foreach ($assignment in $roleAssignments) {
                                try {
                                    $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                    if ($user) {
                                        $affectedAccounts += [PSCustomObject]@{
                                            Name = $user.DisplayName
                                            Id = $user.Id
                                            Details = "Role: $($role.DisplayName)"
                                        }
                                    } else {
                                        $sp = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                        if ($sp) {
                                            $affectedAccounts += [PSCustomObject]@{
                                                Name = $sp.DisplayName
                                                Id = $sp.Id
                                                Details = "Service Principal with Role: $($role.DisplayName)"
                                            }
                                        }
                                    }
                                } catch {
                                    # Skip if we can't resolve the principal
                                }
                            }
                        }
                    } catch {
                        # Skip if we can't get role assignments
                    }
                }
            }
        } else {
            $controlFinding = "No policies with phishing-resistant MFA strength found for administrators."
            $controlResult = "NOT COMPLIANT"
            
            $evidence = "No Conditional Access policies were found that enforce phishing-resistant MFA for administrator roles.`n`n"
            $evidence += "List of administrator roles that should be protected:`n"
            
            foreach ($role in $adminRoles) {
                $evidence += "- $($role.DisplayName)`n"
            }
            
            # Create affected accounts list with regular role assignments
            $affectedAccounts = @()
            foreach ($role in $adminRoles) {
                try {
                    # Use regular role assignments instead of PIM assignments
                    $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $role.Id
                    if ($roleDefinition) {
                        $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
                        
                        foreach ($assignment in $roleAssignments) {
                            try {
                                $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                if ($user) {
                                    $affectedAccounts += [PSCustomObject]@{
                                        Name = $user.DisplayName
                                        Id = $user.Id
                                        Details = "Role: $($role.DisplayName)"
                                    }
                                } else {
                                    $sp = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                    if ($sp) {
                                        $affectedAccounts += [PSCustomObject]@{
                                            Name = $sp.DisplayName
                                            Id = $sp.Id
                                            Details = "Service Principal with Role: $($role.DisplayName)"
                                        }
                                    }
                                }
                            } catch {
                                # Skip if we can't resolve the principal
                            }
                        }
                    }
                } catch {
                    # Skip if we can't get role assignments
                }
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Protection > Conditional Access</strong></li>
    <li>Create a new Conditional Access policy with the following settings:
        <ul>
            <li><strong>Name</strong>: Admin Phishing-Resistant MFA Policy</li>
            <li><strong>Users</strong>: Include all directory roles with "Administrator" in the name</li>
            <li><strong>Cloud apps</strong>: All cloud apps</li>
            <li><strong>Conditions</strong>: Configure as needed for your environment</li>
            <li><strong>Grant</strong>: Require authentication strength, select "Phishing-resistant MFA"</li>
        </ul>
    </li>
    <li>Set the policy to "On" and save</li>
    <li>Monitor the policy in the Sign-in logs to ensure it's working as expected</li>
</ol>
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
        Write-Error "An error occurred: $_"
    }
}

function Check-BannedPasswordSettings {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure custom banned passwords lists are used"
        $controlDescription = "Creating a new password can be difficult regardless of one's technical background. It is common to look around one's environment for suggestions when building a password, however, this may include picking words specific to the organization as inspiration for a password. An adversary may employ what is called a 'mangler' to create permutations of these specific words in an attempt to crack passwords or hashes making it easier to reach their goal."
    
        # Retrieve the group setting
        $groupSetting = Get-MgGroupSetting
        $evidence = ""
        
        # Find the "EnableBannedPasswordCheck" value
        $enableBannedPasswordCheckValue = $groupSetting.Values | Where-Object { $_.Name -eq "EnableBannedPasswordCheck" }

        # Find the "BannedPasswordList" value
        $bannedPasswordListValue = $groupSetting.Values | Where-Object { $_.Name -eq "BannedPasswordList" }
        
        # Build evidence
        $evidence = "Current Password Protection Settings:`n"
        $evidence += "`nEnable Banned Password Check: $($enableBannedPasswordCheckValue.Value)"
        
        if ($bannedPasswordListValue) {
            $evidence += "`nBanned Password List Count: $($bannedPasswordListValue.Value.Count)`n"
            
            # Only showing a redacted count for security reasons
            $evidence += "`nNote: For security reasons, the actual banned passwords are not displayed in this report."
        } else {
            $evidence += "`nBanned Password List: Not configured"
        }
        
        # Check if EnableBannedPasswordCheck is enabled
        if ($enableBannedPasswordCheckValue -and $enableBannedPasswordCheckValue.Value -eq $true) {
            # Check if BannedPasswordList is empty
            if (-not $bannedPasswordListValue -or $bannedPasswordListValue.Value.Count -eq 0) {
                $controlFinding = "Custom banned passwords setting is enabled but the list of passwords is empty."
                $controlResult = "NOT COMPLIANT"
                
                # Add additional evidence
                $evidence += "`n`nThe custom banned passwords feature is enabled, but no banned passwords have been added to the list. This renders the feature ineffective for preventing common or easily-guessable passwords."
            }
            else {            
                $controlFinding = "Custom banned passwords setting is enabled and the list of passwords is configured."
                $controlResult = "COMPLIANT"
                
                # Add additional evidence
                $evidence += "`n`nThe custom banned passwords feature is properly enabled and configured with a list of banned passwords."
            }
        }
        else {
            $controlFinding = "Custom banned passwords setting is disabled."
            $controlResult = "NOT COMPLIANT"
            
            # Add additional evidence
            $evidence += "`n`nThe custom banned passwords feature is currently disabled. This allows users to set common, easily-guessable passwords that could be vulnerable to dictionary or brute force attacks."
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Identity > Protection > Password protection</strong></li>
    <li>Set <strong>Enforce custom list</strong> to <strong>Yes</strong></li>
    <li>Add custom banned passwords that are relevant to your organization, such as:
        <ul>
            <li>Your organization's name and variations</li>
            <li>Product names</li>
            <li>Address terms</li>
            <li>Other organization-specific terms that might be used in passwords</li>
        </ul>
    </li>
    <li>Save your changes</li>
</ol>
"@
        }

        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = $controlFinding
            Result = $controlResult
            Evidence = $evidence
            RemediationSteps = $remediationSteps
        }
    }
    catch {
        Write-Error "An error occurred while checking the settings: $_"
    }
}

function Check-BlockNonAdminTenantCreation {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"
        $controlDescription = "Restricting tenant creation prevents unauthorized or uncontrolled deployment of resources and ensures that the organization retains control over its infrastructure. User generation of shadow IT could lead to multiple, disjointed environments that can make it difficult for IT to manage and secure the organization's data, especially if other users in the organization began using these tenants for business purposes under the misunderstanding that they were secured by the organization's security team."
    
        # Get Default User Role Permissions
        $defaultUserRolePermissions = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions
        
        # Build evidence
        $evidence = "Current Settings for Tenant Creation:`n"
        $evidence += "`nAllowedToCreateTenants: $($defaultUserRolePermissions.AllowedToCreateTenants)"
        
        # Check if non-admin users can create tenants
        $allowedToCreateTenants = (-not $defaultUserRolePermissions.AllowedToCreateTenants) -or 
                                 ($defaultUserRolePermissions.AllowedToCreateTenants -eq $false)

        $affectedAccounts = $null
        if ($allowedToCreateTenants) {
            $controlFinding = "Non-admin users are restricted from creating tenants."
            $controlResult = "COMPLIANT"
            
            $evidence += "`n`nNon-administrative users are properly restricted from creating new Entra ID tenants, which helps prevent shadow IT and maintains centralized control over your organization's cloud resources."
        } else {
            $controlFinding = "Non-admin users are NOT restricted from creating tenants."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "`n`nNon-administrative users are currently allowed to create new Entra ID tenants. This could lead to:
- Unmanaged cloud environments (shadow IT)
- Potential data security issues
- Lack of compliance oversight
- Fragmented identity management"
            
            # Get users who could potentially create tenants (non-admins)
            $standardUsers = Get-MgUser -Top 100 | Where-Object { 
                # Filter out guest users and service accounts
                $_.UserType -eq "Member" -and 
                -not ($_.DisplayName -match "service" -or $_.UserPrincipalName -match "service")
            }
            
            $affectedAccounts = @()
            foreach ($user in $standardUsers) {
                $affectedAccounts += [PSCustomObject]@{
                    Name = $user.DisplayName
                    Id = $user.Id
                    Details = "Standard user with tenant creation rights"
                }
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Identity > Users > User settings</strong></li>
    <li>Under <strong>Users can create Azure AD tenants</strong>, set to <strong>No</strong></li>
    <li>Click <strong>Save</strong> to apply the change</li>
</ol>
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
        Write-Error "An error occurred: $_"
    }
}

function Check-DynamicGroupForGuestUsers {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure a dynamic group for guest users is created"
        $controlDescription = "A dynamic group is a dynamic configuration of security group membership for Azure Active Directory. Administrators can set rules to populate groups that are created in Azure AD based on user attributes (such as userType, department, or country/region). Members can be automatically added to or removed from a security group based on their attributes. The recommended state is to create a dynamic group that includes guest accounts."

        # Get all groups with dynamic membership
        $groups = Get-MgGroup | Where-Object { $_.GroupTypes -contains "DynamicMembership" }
        
        # Build evidence
        $evidence = "Dynamic Group Configuration:`n"
        
        # Filter dynamic groups for guest users
        $guestDynamicGroups = $groups | Where-Object { $_.MembershipRule -like "*user.userType -eq `"Guest`"*" }
        
        $evidence += "`nTotal Dynamic Groups: $($groups.Count)"
        $evidence += "`nDynamic Groups for Guest Users: $($guestDynamicGroups.Count)"
        
        $affectedAccounts = $null
        if ($guestDynamicGroups.Count -gt 0) {
            $controlFinding = "Dynamic group for guest users found."
            $controlResult = "COMPLIANT"
            
            $evidence += "`n`nDynamic Groups for Guest Users:`n"
            foreach ($group in $guestDynamicGroups) {
                $evidence += "`n- Group Name: $($group.DisplayName)"
                $evidence += "`n  Membership Rule: $($group.MembershipRule)"
            }
            
            # Get current guest users for reference
            $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Top 20
            $evidence += "`n`nSample of Current Guest Users ($($guestUsers.Count) shown):`n"
            foreach ($guest in $guestUsers) {
                $evidence += "`n- $($guest.DisplayName) ($($guest.UserPrincipalName))"
            }
        }
        else {
            $controlFinding = "No dynamic group for guest users found."
            $controlResult = "NOT COMPLIANT"
            
            if ($groups.Count -gt 0) {
                $evidence += "`n`nExisting Dynamic Groups (None for Guest Users):`n"
                foreach ($group in $groups) {
                    $evidence += "`n- Group Name: $($group.DisplayName)"
                    $evidence += "`n  Membership Rule: $($group.MembershipRule)"
                }
            } else {
                $evidence += "`n`nNo dynamic groups configured in the tenant."
            }
            
            # Get current guest users to show impact
            $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Top 20
            
            if ($guestUsers.Count -gt 0) {
                $evidence += "`n`nGuest Users Without Dynamic Group Management ($($guestUsers.Count) shown):`n"
                foreach ($guest in $guestUsers) {
                    $evidence += "`n- $($guest.DisplayName) ($($guest.UserPrincipalName))"
                }
                
                $affectedAccounts = @()
                foreach ($guest in $guestUsers) {
                    $affectedAccounts += [PSCustomObject]@{
                        Name = $guest.DisplayName
                        Id = $guest.Id
                        Details = "Guest user not in a dynamic group"
                    }
                }
            } else {
                $evidence += "`n`nNo guest users currently found in the tenant."
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Groups > All groups</strong> and click <strong>New group</strong></li>
    <li>Set the following values:
        <ul>
            <li><strong>Group type</strong>: Security</li>
            <li><strong>Group name</strong>: All Guest Users</li>
            <li><strong>Membership type</strong>: Dynamic User</li>
            <li><strong>Dynamic user members</strong>: Click <strong>Add dynamic query</strong></li>
            <li>Set the rule to: <code>user.userType -eq "Guest"</code></li>
        </ul>
    </li>
    <li>Click <strong>Save</strong> to create the group</li>
    <li>Consider setting up access reviews for this group to periodically review guest access</li>
</ol>
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
        Write-Error "An error occurred: $_"
    }
}

function Check-MicrosoftAuthenticatorFatigue {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure Microsoft Authenticator is configured to protect against MFA fatigue"
        $controlDescription = "Microsoft has released additional settings to enhance the configuration of the Microsoft Authenticator application. These settings provide additional information and context to users who receive MFA passwordless and push requests, such as geographic location the request came from, the requesting application and requiring a number match. Ensure the following are Enabled.
        • Require number matching for push notifications
        • Show application name in push and passwordless notifications
        • Show geographic location in push and passwordless notifications"
    
        # Retrieve configuration for Microsoft Authenticator
        $authenticatorConfig = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId MicrosoftAuthenticator
        
        # Build evidence
        $evidence = "Microsoft Authenticator Configuration:`n"
        $evidence += "`nAuthenticator State: $($authenticatorConfig.State)"
        
        $affectedAccounts = $null
        # Check if Microsoft Authenticator is disabled
        if ($authenticatorConfig.State -eq "disabled") {
            $controlFinding = "Microsoft Authenticator is disabled."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "`n`nMicrosoft Authenticator is currently disabled in your tenant, which means:
- Users cannot use the Microsoft Authenticator app for MFA
- Anti-MFA fatigue protections cannot be implemented
- The organization is missing out on a more secure authentication method"
            
            # Get users who would be affected
            $affectedUsers = Get-MgUser -Top 50 | Where-Object { $_.UserType -eq "Member" }
            
            $affectedAccounts = @()
            foreach ($user in $affectedUsers) {
                $affectedAccounts += [PSCustomObject]@{
                    Name = $user.DisplayName
                    Id = $user.Id
                    Details = "Cannot use Microsoft Authenticator for MFA"
                }
            }
        } 
        else {
            # If Microsoft Authenticator is enabled, check for MFA fatigue resistance settings
            $featureSettings = $authenticatorConfig.AdditionalProperties.featureSettings
            $numberMatchingRequiredState = $featureSettings.numberMatchingRequiredState
            $displayLocationInformationRequiredState = $featureSettings.displayLocationInformationRequiredState
            $displayAppInformationRequiredState = $featureSettings.displayAppInformationRequiredState
            
            $evidence += "`n`nMFA Fatigue Protection Settings:`n"
            $evidence += "`nNumber Matching Required: $($numberMatchingRequiredState.State)"
            $evidence += "`nDisplay Location Information: $($displayLocationInformationRequiredState.State)"
            $evidence += "`nDisplay Application Information: $($displayAppInformationRequiredState.State)"

            if ($numberMatchingRequiredState.State -eq "enabled" -and 
                $displayLocationInformationRequiredState.State -eq "enabled" -and 
                $displayAppInformationRequiredState.State -eq "enabled") {
                
                $controlFinding = "Microsoft Authenticator is configured to be resistant to MFA fatigue."
                $controlResult = "COMPLIANT"
                
                $evidence += "`n`nAll three recommended anti-MFA fatigue settings are properly enabled:
1. Number matching provides a verification code that users must enter, preventing automatic approvals
2. Location information helps users identify if a sign-in attempt is coming from an unexpected location
3. Application information helps users know which application the sign-in is for"
            } 
            else {
                $controlFinding = "Microsoft Authenticator is not configured to be resistant to MFA fatigue."
                $controlResult = "NOT COMPLIANT"
                
                $evidence += "`n`nThe following anti-MFA fatigue settings are missing:"
                
                if ($numberMatchingRequiredState.State -ne "enabled") {
                    $evidence += "`n- Number matching is not enabled (critical for preventing automated approvals)"
                }
                
                if ($displayLocationInformationRequiredState.State -ne "enabled") {
                    $evidence += "`n- Location information is not displayed (useful for identifying suspicious sign-ins)"
                }
                
                if ($displayAppInformationRequiredState.State -ne "enabled") {
                    $evidence += "`n- Application information is not displayed (helps users identify what they're signing into)"
                }
                
                # Get users who use Microsoft Authenticator
                $usersWithAuthenticator = @()
                try {
                    $users = Get-MgUser -Top 50 | Where-Object { $_.UserType -eq "Member" }
                    foreach ($user in $users) {
                        $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
                        if ($methods | Where-Object { $_.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" }) {
                            $usersWithAuthenticator += $user
                        }
                    }
                    
                    $affectedAccounts = @()
                    foreach ($user in $usersWithAuthenticator) {
                        $affectedAccounts += [PSCustomObject]@{
                            Name = $user.DisplayName
                            Id = $user.Id
                            Details = "Using Microsoft Authenticator without all anti-fatigue protections"
                        }
                    }
                } catch {
                    # If we can't get authentication methods, just note it
                    $evidence += "`n`nUnable to determine specific users with Microsoft Authenticator configured due to permission limitations."
                }
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Protection > Authentication methods</strong></li>
    <li>Click on <strong>Microsoft Authenticator</strong></li>
    <li>Ensure Microsoft Authenticator is <strong>Enabled</strong></li>
    <li>Under <strong>Configure</strong>, enable all three anti-MFA fatigue settings:
        <ul>
            <li>Set <strong>Require number matching for push notifications</strong> to <strong>Enabled</strong></li>
            <li>Set <strong>Show app name in push and passwordless notifications</strong> to <strong>Enabled</strong></li>
            <li>Set <strong>Show geographic location in push and passwordless notifications</strong> to <strong>Enabled</strong></li>
        </ul>
    </li>
    <li>Click <strong>Save</strong> to apply the changes</li>
</ol>
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
        Write-Error "An error occurred: $_"
    }
}

function Check-OnPremisesSync {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure that password hash sync is enabled for hybrid deployments"
        $controlDescription = "Password hash synchronization helps by reducing the number of passwords your users need to maintain to just one and enables leaked credential detection for your hybrid accounts. Leaked credential protection is leveraged through Azure AD Identity Protection and is a subset of that feature which can help identify if an organization's user account passwords have appeared on the dark web or public spaces. Using other options for your directory synchronization may be less resilient as Microsoft can still process sign-ins to 365 with Hash Sync even if a network connection to your on-premises environment is not available."
    
        $organization = Get-MgOrganization
        $onPremisesSyncEnabled = $organization.OnPremisesSyncEnabled
        $onPremisesLastSyncDateTime = $organization.OnPremisesLastSyncDateTime
        
        # Build evidence
        $evidence = "On-Premises Synchronization Status:`n"
        $evidence += "`nSync Enabled: $onPremisesSyncEnabled"
        
        if ($onPremisesLastSyncDateTime) {
            $evidence += "`nLast Sync Date: $onPremisesLastSyncDateTime"
            
            # Calculate time since last sync
            $timeSinceSync = (Get-Date) - $onPremisesLastSyncDateTime
            $evidence += "`nTime Since Last Sync: $($timeSinceSync.Days) days, $($timeSinceSync.Hours) hours, $($timeSinceSync.Minutes) minutes"
            
            # Check if sync is recent (within last 3 hours)
            if ($timeSinceSync.TotalHours -le 3) {
                $evidence += "`nSync Status: Recent (within last 3 hours)"
            } elseif ($timeSinceSync.TotalHours -le 24) {
                $evidence += "`nSync Status: Within last 24 hours"
            } else {
                $evidence += "`nSync Status: Stale (more than 24 hours old)"
            }
        } else {
            $evidence += "`nLast Sync Date: Never synced or information not available"
        }
        
        # Determine if this is a hybrid deployment
        $isHybridDeployment = $false
        if ($onPremisesSyncEnabled -or ($organization.OnPremisesDomainName)) {
            $isHybridDeployment = $true
            $evidence += "`n`nDeployment Type: Hybrid (with on-premises connection)"
            
            # Check if password hash sync is enabled
            try {
                # This cmdlet might not be available, but trying for completeness
                $adConnectStatus = Get-MgDirectorySetting | Where-Object { $_.DisplayName -eq "AAD Connect" }
                
                if ($adConnectStatus) {
                    $pwdSyncEnabled = $adConnectStatus.Values | Where-Object { $_.Name -eq "PasswordHashSyncEnabled" }
                    
                    if ($pwdSyncEnabled -and $pwdSyncEnabled.Value -eq $true) {
                        $evidence += "`nPassword Hash Sync: Enabled"
                        $passwordHashSyncEnabled = $true
                    } else {
                        $evidence += "`nPassword Hash Sync: Not enabled or status unknown"
                        $passwordHashSyncEnabled = $false
                    }
                } else {
                    $evidence += "`nPassword Hash Sync: Status unknown (cannot retrieve AAD Connect settings)"
                    $passwordHashSyncEnabled = $onPremisesSyncEnabled # Assume it's enabled if sync is enabled
                }
            } catch {
                $evidence += "`nPassword Hash Sync: Status unknown (error retrieving settings)"
                $passwordHashSyncEnabled = $onPremisesSyncEnabled # Assume it's enabled if sync is enabled
            }
        } else {
            $evidence += "`n`nDeployment Type: Cloud-only (no on-premises connection)"
            $passwordHashSyncEnabled = $true # Not applicable for cloud-only
        }
        
        $affectedAccounts = $null
        # Determine compliance based on deployment type
        if (!$isHybridDeployment) {
            $controlFinding = "This is a cloud-only deployment, no password hash sync required."
            $controlResult = "COMPLIANT"
        } elseif ($onPremisesSyncEnabled -and $passwordHashSyncEnabled) {
            $controlFinding = "On-Premises Sync is enabled with password hash synchronization."
            $controlResult = "COMPLIANT"
        } else {
            $controlFinding = "On-Premises Sync is not properly configured with password hash synchronization."
            $controlResult = "NOT COMPLIANT"
            
            # Get sample of synchronized users
            $syncedUsers = Get-MgUser -Filter "onPremisesDistinguishedName ne null" -Top 20
            
            if ($syncedUsers.Count -gt 0) {
                $evidence += "`n`nSample of Synchronized Users Without Password Hash Sync:`n"
                
                $affectedAccounts = @()
                foreach ($user in $syncedUsers) {
                    $evidence += "`n- $($user.DisplayName) ($($user.UserPrincipalName))"
                    
                    $affectedAccounts += [PSCustomObject]@{
                        Name = $user.DisplayName
                        Id = $user.Id
                        Details = "Synchronized user without password hash sync"
                    }
                }
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>On your on-premises server running Azure AD Connect, open the Azure AD Connect configuration wizard</li>
    <li>Select <strong>Configure</strong></li>
    <li>Select <strong>Customize synchronization options</strong> and click <strong>Next</strong></li>
    <li>Enter your Azure AD credentials when prompted</li>
    <li>On the <strong>Optional Features</strong> page, ensure <strong>Password hash synchronization</strong> is checked</li>
    <li>Complete the wizard to apply your changes</li>
    <li>After configuration is complete, force a full sync with these PowerShell commands on the sync server:
        <pre>Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Initial</pre>
    </li>
    <li>Verify in the Azure portal that synchronization is working properly</li>
</ol>
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
        Write-Error "An error occurred: $_"
    }
}

function Check-PermanentActiveAssignments {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure 'Privileged Identity Management' is used to manage roles"
        $controlDescription = "Azure Active Directory Privileged Identity Management can be used to audit roles, allow just in time activation of roles and allow for periodic role attestation. Organizations should remove permanent members from privileged Office 365 roles and instead make them eligible, through a JIT activation workflow."

        # Check if tenant has Entra ID P2 license
        $hasP2License = $false
        try {
            # Try to call a P2-only API
            Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -Top 1 -ErrorAction Stop
            $hasP2License = $true
        }
        catch {
            # Check if the error is specifically about premium license requirements
            if ($_.Exception.Message -match "AadPremiumLicenseRequired" -or 
                $_.Exception.Message -match "Microsoft Entra ID P2" -or
                $_.Exception.Message -match "Entra ID Governance license") {
                $hasP2License = $false
            }
            else {
                # If it's some other error, we'll consider it might be transient and not license-related
                $hasP2License = $true
            }
        }
        
        if (-not $hasP2License) {
            # If no P2 license, provide information about PIM and licensing requirements
            $controlFinding = "Unable to assess PIM usage - Microsoft Entra ID P2 license required."
            $controlResult = "INFORMATION NEEDED"
            
            $evidence = "This control requires Microsoft Entra ID P2 or Microsoft Entra ID Governance license to assess.`n`n"
            $evidence += "Privileged Identity Management (PIM) is a premium feature that allows organizations to:`n"
            $evidence += "- Provide just-in-time privileged access to resources`n"
            $evidence += "- Assign time-bound access to resources using start and end dates`n"
            $evidence += "- Require approval to activate privileged roles`n"
            $evidence += "- Enforce multi-factor authentication to activate any role`n"
            $evidence += "- Get notifications when privileged roles are activated`n"
            $evidence += "- Conduct access reviews to ensure users still need roles`n`n"
            
            $evidence += "Without PIM, permanent role assignments increase security risks by providing standing access to sensitive resources.`n"
            
            # List privileged roles without using PIM APIs
            $privilegedRoles = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { $_.IsPrivileged -eq $true }
            $evidence += "`nPrivileged roles in your tenant that should be managed with PIM:`n"
            
            $roleAssignments = @()
            foreach ($role in $privilegedRoles) {
                # Get regular role assignments instead of PIM assignments
                $assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'"
                
                if ($assignments) {
                    $evidence += "`n- $($role.DisplayName)"
                    foreach ($assignment in $assignments) {
                        try {
                            $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                            if ($user) {
                                $roleAssignments += [PSCustomObject]@{
                                    RoleName = $role.DisplayName
                                    PrincipalName = $user.DisplayName
                                    PrincipalId = $user.Id
                                    Type = "User"
                                }
                            } else {
                                $sp = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -ErrorAction SilentlyContinue
                                if ($sp) {
                                    $roleAssignments += [PSCustomObject]@{
                                        RoleName = $role.DisplayName
                                        PrincipalName = $sp.DisplayName
                                        PrincipalId = $sp.Id
                                        Type = "Service Principal"
                                    }
                                }
                            }
                        } catch {
                            # Skip if we can't resolve the principal
                        }
                    }
                }
            }
            
            if ($roleAssignments.Count -gt 0) {
                $evidence += "`n`nCurrent privileged role assignments (all permanent since PIM is not available):`n"
                foreach ($assignment in $roleAssignments) {
                    $evidence += "`n- Role: $($assignment.RoleName)"
                    $evidence += "`n  Assigned to: $($assignment.PrincipalName) ($($assignment.Type))"
                }
                
                # Create affected accounts for reporting
                $affectedAccounts = @()
                foreach ($assignment in $roleAssignments) {
                    $affectedAccounts += [PSCustomObject]@{
                        Name = $assignment.PrincipalName
                        Id = $assignment.PrincipalId
                        Details = "Permanent assignment to role: $($assignment.RoleName)"
                    }
                }
            } else {
                $evidence += "`n`nNo privileged role assignments found in the tenant."
            }
            
            # Provide remediation steps for obtaining PIM
            $remediationSteps = @"
<ol>
    <li>To use Privileged Identity Management (PIM), your organization needs one of the following licenses:
        <ul>
            <li>Microsoft Entra ID P2</li>
            <li>Microsoft Entra ID Governance</li>
            <li>Enterprise Mobility + Security E5</li>
            <li>Microsoft 365 E5</li>
        </ul>
    </li>
    <li>After obtaining the appropriate license:
        <ul>
            <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
            <li>Go to <strong>Identity Governance > Privileged Identity Management</strong></li>
            <li>Set up PIM for your privileged roles, converting permanent assignments to eligible assignments</li>
            <li>Configure appropriate activation settings, including approval requirements and time limits</li>
        </ul>
    </li>
    <li>For more information, visit <a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure" target="_blank">Microsoft's documentation on configuring PIM</a></li>
</ol>
"@

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
        
        # If the tenant has P2 license, proceed with the original check
        # Get permanent (no endDateTime) active role assignments
        $permanentActiveAssignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance | 
            Where-Object { $_.EndDateTime -eq $null } | 
            Select-Object AssignmentType, PrincipalId, RoleDefinitionId, StartDateTime, EndDateTime
    
        $users = Get-MgUser -Property Id, DisplayName, UserPrincipalName -All
        $roles = Get-MgRoleManagementDirectoryRoleDefinition -Property Id, DisplayName, IsPrivileged
    
        $userIdNameMap = @{}
        foreach ($user in $users) {
            $userIdNameMap[$user.Id] = @{
                DisplayName = $user.DisplayName
                UPN = $user.UserPrincipalName
            }
        }
    
        $roleIdNameMap = @{}
        $privilegedRoleIds = @()
        foreach ($role in $roles) {
            $roleIdNameMap[$role.Id] = $role.DisplayName
            if ($role.IsPrivileged) {
                $privilegedRoleIds += $role.Id
            }
        }
        
        # Build evidence
        $evidence = "Privileged Role Assignment Analysis:`n"
        
        # Only focus on privileged roles
        $permanentPrivilegedAssignments = $permanentActiveAssignments | 
            Where-Object { $privilegedRoleIds -contains $_.RoleDefinitionId }
        
        $evidence += "`nTotal Permanent Role Assignments: $($permanentActiveAssignments.Count)"
        $evidence += "`nPermanent Privileged Role Assignments: $($permanentPrivilegedAssignments.Count)"
        
        $affectedAccounts = $null
        if ($permanentPrivilegedAssignments.Count -gt 0) {
            $controlFinding = "Permanent active privileged role assignments found."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "`n`nPermanent Privileged Role Assignments:`n"
            
            $affectedAccounts = @()
            foreach ($assignment in $permanentPrivilegedAssignments) {
                $roleName = $roleIdNameMap[$assignment.RoleDefinitionId]
                $userName = if ($userIdNameMap[$assignment.PrincipalId]) {
                    $userIdNameMap[$assignment.PrincipalId].DisplayName
                } else {
                    "Unknown (Service Principal or Group)"
                }
                
                $evidence += "`n- Role: $roleName"
                $evidence += "`n  Assigned to: $userName"
                $evidence += "`n  Assignment Type: $($assignment.AssignmentType)"
                $evidence += "`n  Start Date: $($assignment.StartDateTime)"
                $evidence += "`n  End Date: Never (Permanent Assignment)"
                $evidence += "`n"
                
                $affectedAccounts += [PSCustomObject]@{
                    Name = $userName
                    Id = $assignment.PrincipalId
                    Details = "Permanent assignment to role: $roleName"
                }
            }
            
            # Check if PIM is available in the tenant
            try {
                $pimSettings = Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'"
                if ($pimSettings) {
                    $evidence += "`nPrivileged Identity Management (PIM) Status: Available"
                } else {
                    $evidence += "`nPrivileged Identity Management (PIM) Status: Not configured"
                }
            } catch {
                $evidence += "`nPrivileged Identity Management (PIM) Status: Unable to determine"
            }
        }
        else {
            $controlFinding = "No permanent active privileged role assignments found."
            $controlResult = "COMPLIANT"
            
            $evidence += "`n`nAll privileged role assignments are properly managed through time-bound assignments, which is the recommended security practice."
            
            # Check if PIM is being used
            try {
                $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance
                
                if ($eligibleAssignments.Count -gt 0) {
                    $evidence += "`n`nPrivileged Identity Management is being used with $($eligibleAssignments.Count) eligible role assignments."
                }
            } catch {
                $evidence += "`n`nUnable to determine if Privileged Identity Management is being used for eligible assignments."
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Identity Governance > Privileged Identity Management</strong></li>
    <li>Select <strong>Azure AD roles</strong></li>
    <li>For each permanent role assignment:
        <ul>
            <li>Remove the permanent assignment by finding the role, selecting <strong>Assignments</strong>, and removing the permanent member</li>
            <li>Add an eligible assignment instead by selecting <strong>Add assignments</strong>, choosing the same user and role, but setting <strong>Assignment type</strong> to <strong>Eligible</strong></li>
            <li>Configure an appropriate assignment duration (e.g., 6 months)</li>
        </ul>
    </li>
    <li>Consider implementing access reviews for privileged roles to ensure regular attestation</li>
</ol>
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
        Write-Error "An error occurred: $_"
    }
}

function Check-SecurityDefaultStatus {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure Security Defaults is disabled on Azure Active Directory"
        $controlDescription = "Security defaults provide secure default settings that are managed on behalf of organizations to keep customers safe until they are ready to manage their own identity security settings.
        For example, doing the following:
        • Requiring all users and admins to register for MFA.
        • Challenging users with MFA - mostly when they show up on a new device or app, but more often for critical roles and tasks.
        • Disabling authentication from legacy authentication clients, which can't do MFA."

        # Get Security Defaults policy and check if it's disabled
        $securityDefaultsPolicy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Select-Object -ExpandProperty IsEnabled
        
        # Build evidence
        $evidence = "Security Defaults Configuration:`n"
        $evidence += "`nSecurity Defaults Enabled: $securityDefaultsPolicy"
        
        # Check if Conditional Access is being used
        $conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy
        $evidence += "`nNumber of Conditional Access Policies: $($conditionalAccessPolicies.Count)"
        
        # Check for active Conditional Access policies
        $activePolicies = $conditionalAccessPolicies | Where-Object { $_.State -eq "enabled" }
        $evidence += "`nActive Conditional Access Policies: $($activePolicies.Count)"
        
        if ($securityDefaultsPolicy -eq $true) {
            $controlFinding = "Security Defaults are enabled."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "`n`nSecurity Defaults are currently enabled. This means:
- Basic security protections are in place, which is better than no security
- However, your organization cannot use Conditional Access policies for more granular control
- You cannot customize security settings to meet specific organizational needs
- You have less flexibility in how authentication and access are managed"
            
            # See if we have any conditional access policies that would conflict
            if ($conditionalAccessPolicies.Count -gt 0) {
                $evidence += "`n`nPotential Configuration Conflict: Security Defaults are enabled but $($conditionalAccessPolicies.Count) Conditional Access policies exist. These policies will not take effect as long as Security Defaults remain enabled."
            }
        }
        else {
            # Check if we have adequate CA policies instead
            if ($activePolicies.Count -ge 3) {
                $controlFinding = "Security Defaults are disabled and replaced with custom Conditional Access policies."
                $controlResult = "COMPLIANT"
                
                $evidence += "`n`nSecurity Defaults are properly disabled and replaced with custom Conditional Access policies. This is the recommended configuration as it allows for more granular control over security requirements."
                
                $evidence += "`n`nActive Conditional Access Policies (first 5 shown):`n"
                foreach ($policy in $activePolicies | Select-Object -First 5) {
                    $evidence += "`n- $($policy.DisplayName)"
                }
            } else {
                $controlFinding = "Security Defaults are disabled but may not have adequate Conditional Access replacements."
                $controlResult = "PARTIALLY COMPLIANT"
                
                $evidence += "`n`nSecurity Defaults are disabled, but there appear to be few active Conditional Access policies ($($activePolicies.Count)). Ensure you have implemented appropriate policies to replace the protections offered by Security Defaults."
                
                if ($activePolicies.Count -gt 0) {
                    $evidence += "`n`nActive Conditional Access Policies:`n"
                    foreach ($policy in $activePolicies) {
                        $evidence += "`n- $($policy.DisplayName)"
                    }
                }
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -eq "NOT COMPLIANT" -or $controlResult -eq "PARTIALLY COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>First, create baseline Conditional Access policies before disabling Security Defaults:
        <ul>
            <li>Create a policy requiring MFA for all users</li>
            <li>Create a policy blocking legacy authentication</li>
            <li>Create a policy requiring MFA for administrators</li>
            <li>Consider additional policies for high-risk sign-ins and risky users</li>
        </ul>
    </li>
    <li>Once your Conditional Access policies are in place, disable Security Defaults:
        <ul>
            <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
            <li>Go to <strong>Protection > Properties</strong></li>
            <li>At the bottom of the page, set <strong>Enable Security defaults</strong> to <strong>No</strong></li>
            <li>Select a reason for disabling, such as "Using Conditional Access"</li>
            <li>Click <strong>Save</strong></li>
        </ul>
    </li>
    <li>Monitor your sign-in logs to ensure your Conditional Access policies are working as expected</li>
</ol>
"@
        }

        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = $controlFinding
            Result = $controlResult
            Evidence = $evidence
            RemediationSteps = $remediationSteps
        }
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}