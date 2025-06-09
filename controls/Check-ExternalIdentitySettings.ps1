function Check-ExternalIdentitySettings {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure external identity settings are securely configured"
        $controlDescription = "External identity settings control how users from outside your organization can collaborate with your resources. Ensuring these settings are properly configured helps limit external access to only necessary users and prevents potential security issues from unmanaged external identities."
        
        # Get external collaboration settings
        $externalCollabSettings = Get-MgPolicyAuthorizationPolicy
        
        # Get invitation settings
        $invitationSettings = Get-MgPolicyAuthorizationPolicy
        
        $evidence = "External Identity Configuration:`n"
        
        # Check guest user access restrictions
        $guestUserAccessLevel = $externalCollabSettings.GuestUserRoleId
        $guestUserAccessDescription = switch ($guestUserAccessLevel) {
            "a0b1b346-4d3e-4e8b-98f8-753987be4970" { "Guest users have the same access as members (most permissive)" }
            "10dae51f-b6af-4016-8d66-8c2a99b929b3" { "Guest users have limited access to properties and memberships of directory objects" }
            "2af84b1e-32c8-42b7-82bc-daa82404023b" { "Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)" }
            default { "Unknown guest access level: $guestUserAccessLevel" }
        }
        
        $evidence += "`nGuest User Access Level: $guestUserAccessDescription"
        
        # Check who can invite guests
        $allowInvitesFrom = $invitationSettings.AllowInvitesFrom
        $inviteRestrictionDescription = switch ($allowInvitesFrom) {
            "everyone" { "Anyone in the organization can invite guest users including guests and non-admins (least restrictive)" }
            "adminsAndGuestInviters" { "Only admins and users in the guest inviter role can invite guests" }
            "adminsGuestInvitersAndAllMembers" { "Admins, guest inviters, and members can invite guests" }
            "admin" { "Only admins can invite guests (most restrictive)" }
            "none" { "No one can invite guests" }
            default { "Unknown invitation restriction: $allowInvitesFrom" }
        }
        
        $evidence += "`nGuest Invitation Restrictions: $inviteRestrictionDescription"
        
        # Check email one-time passcode settings
        try {
            $authPolicy = Get-MgPolicyAuthenticationFlowPolicy
            $emailOtpEnabled = $authPolicy.Description -match "Email OTP is enabled" -or $authPolicy.PolicyDetail -match "EmailOtpAuthentication:enabled"
            
            $evidence += "`nEmail One-Time Passcode: " + (if ($emailOtpEnabled) { "Enabled" } else { "Disabled" })
        } catch {
            $evidence += "`nEmail One-Time Passcode: Unable to determine"
        }
        
        # Check collaboration restrictions (if any)
        try {
            $b2bPolicy = Get-MgPolicyB2cAuthenticationMethods
            if ($b2bPolicy.AllowedMethods -notcontains "emailOtp") {
                $evidence += "`nCollaboration restrictions: Email OTP is not allowed"
            }
        } catch {
            # B2B policy might not exist or be accessible
        }
        
        # Check for domain restrictions
        $allowedDomains = $invitationSettings.AllowedToSignUpEmailBasedSubscriptions
        if ($allowedDomains -and $allowedDomains.Count -gt 0) {
            $evidence += "`nAllowed Domains for Collaboration: $($allowedDomains -join ', ')"
        } else {
            $evidence += "`nAllowed Domains for Collaboration: No restrictions (all domains allowed)"
        }
        
        $blockedDomains = $invitationSettings.BlockedToSignUpEmailBasedSubscriptions
        if ($blockedDomains -and $blockedDomains.Count -gt 0) {
            $evidence += "`nBlocked Domains for Collaboration: $($blockedDomains -join ', ')"
        } else {
            $evidence += "`nBlocked Domains for Collaboration: No blocked domains configured"
        }
        
        # Get guest users to understand current state
        $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Top 5 -Property DisplayName, UserPrincipalName, CreatedDateTime
        $totalGuestUsers = 0
        
        try {
            $totalGuestUsers = (Get-MgUser -Filter "userType eq 'Guest'" -Count -ConsistencyLevel eventual).Count
        } catch {
            # If we can't count all guests due to permissions or other issues
            $totalGuestUsers = "Unknown"
        }
        
        $evidence += "`n`nCurrent Guest User Status:"
        $evidence += "`nTotal Guest Users: $totalGuestUsers"
        if ($guestUsers.Count -gt 0) {
            $evidence += "`nSample of Recent Guest Users:"
            foreach ($guest in $guestUsers) {
                $evidence += "`n- $($guest.DisplayName) ($($guest.UserPrincipalName))"
                $evidence += "`n  Created: $($guest.CreatedDateTime)"
            }
        } else {
            $evidence += "`nNo guest users found in the tenant."
        }
        
        # Evaluate the settings for security
        $isSecure = $false
        
        # Most secure configuration:
        # - Guest access is restricted (most restrictive option)
        # - Only admins can invite guests
        # - Domain restrictions are in place
        
        if (
            $guestUserAccessLevel -eq "2af84b1e-32c8-42b7-82bc-daa82404023b" -and 
            ($allowInvitesFrom -eq "admin" -or $allowInvitesFrom -eq "adminsAndGuestInviters") -and
            ($allowedDomains.Count -gt 0 -or $blockedDomains.Count -gt 0)
        ) {
            $isSecure = $true
            $controlFinding = "External identity settings are securely configured."
            $controlResult = "COMPLIANT"
            
            $evidence += "`n`nThe current configuration implements the recommended security practices:
- Guest user access is appropriately restricted
- Guest invitations are limited to administrators or designated inviters
- Domain restrictions are in place to control which external organizations can collaborate"
        }
        elseif (
            $guestUserAccessLevel -eq "10dae51f-b6af-4016-8d66-8c2a99b929b3" -and
            $allowInvitesFrom -ne "everyone"
        ) {
            $controlFinding = "External identity settings are partially secure but could be improved."
            $controlResult = "PARTIALLY COMPLIANT"
            
            $evidence += "`n`nThe current configuration provides moderate security:
- Guest user access has some restrictions but not the most restrictive setting
- Guest invitations have some controls in place"
            
            if ($allowedDomains.Count -eq 0 -and $blockedDomains.Count -eq 0) {
                $evidence += "`n- No domain restrictions are in place (all external domains can collaborate)"
            }
        }
        else {
            $controlFinding = "External identity settings are not configured securely."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "`n`nThe current configuration has security concerns:
- Guest user access is too permissive
- Guest invitation process has insufficient controls
- Domain restrictions may be missing"
            
            $insecureSettings = @()
            
            if ($guestUserAccessLevel -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970") {
                $insecureSettings += "Guest users have the same access as members (most permissive)"
            }
            
            if ($allowInvitesFrom -eq "everyone") {
                $insecureSettings += "Anyone in the organization can invite guest users"
            }
            
            if ($allowedDomains.Count -eq 0 -and $blockedDomains.Count -eq 0) {
                $insecureSettings += "No domain restrictions are in place (all external domains can collaborate)"
            }
            
            foreach ($setting in $insecureSettings) {
                $evidence += "`n- $setting"
            }
        }
        
        # Add remediation steps for non-compliant findings
        $remediationSteps = $null
        if ($controlResult -ne "COMPLIANT") {
            $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Identity > External Identities > External collaboration settings</strong></li>
    <li>Configure the following recommended settings:
        <ul>
            <li>Set <strong>Guest user access</strong> to <strong>Guest user access is restricted to properties and memberships of their own directory objects</strong> (most restrictive option)</li>
            <li>Set <strong>Guest invite settings</strong> to <strong>Only admins and users in the guest inviter role</strong></li>
            <li>Under <strong>Collaboration restrictions</strong>, either:
                <ul>
                    <li>Allow invitations only to the specified domains (allowlist)</li>
                    <li>Deny invitations to the specified domains (blocklist)</li>
                </ul>
            </li>
            <li>Consider enabling <strong>One-time passcode for email</strong> to allow secure guest access without requiring external accounts</li>
        </ul>
    </li>
    <li>Click <strong>Save</strong> to apply the changes</li>
    <li>Review existing guest accounts and remove any that are no longer needed</li>
    <li>Consider implementing <strong>Access Reviews</strong> for guest users to regularly validate their continued need for access</li>
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
        Write-Error "An error occurred checking external identity settings: $_"
    }
}

# Call the function to run the check
Check-ExternalIdentitySettings