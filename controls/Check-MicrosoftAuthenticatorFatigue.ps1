function Check-MicrosoftAuthenticatorFatigue {
    [CmdletBinding()]
    param()

    try {
        $controlTitle = "Ensure Microsoft Authenticator is configured to protect against MFA fatigue"
        $controlDescription = "Microsoft has released additional settings to enhance the configuration of the Microsoft Authenticator application. These settings provide additional information and context to users who receive MFA passwordless and push requests, such as geographic location the request came from, the requesting application and requiring a number match. Ensure the following are Enabled: • Require number matching for push notifications • Show application name in push and passwordless notifications • Show geographic location in push and passwordless notifications"
    
        # Try different approaches to retrieve Microsoft Authenticator configuration
        $authenticatorConfig = $null
        $evidence = "Microsoft Authenticator Configuration Analysis:`n"
        
        # Approach 1: Try the specific authentication method configuration
        try {
            $authenticatorConfig = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId MicrosoftAuthenticator -ErrorAction Stop
            $evidence += "`nConfiguration retrieval: Successful using specific API"
        }
        catch {
            $evidence += "`nConfiguration retrieval via specific API failed: $($_.Exception.Message)"
            
            # Approach 2: Try getting the general authentication methods policy
            try {
                $authMethodsPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
                $authenticatorConfig = $authMethodsPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "MicrosoftAuthenticator" }
                
                if ($authenticatorConfig) {
                    $evidence += "`nConfiguration retrieval: Successful using general policy API"
                } else {
                    $evidence += "`nMicrosoft Authenticator not found in authentication methods policy"
                }
            }
            catch {
                $evidence += "`nConfiguration retrieval via general policy API failed: $($_.Exception.Message)"
                
                # Approach 3: Try alternative method
                try {
                    $authPolicy = Get-MgPolicyAuthenticationMethod -ErrorAction Stop
                    $evidence += "`nFallback: Retrieved base authentication policy, but specific Authenticator config unavailable"
                }
                catch {
                    $evidence += "`nAll configuration retrieval methods failed. This may indicate insufficient permissions."
                }
            }
        }
        
        # Check if we have sufficient permissions by trying a simpler call
        if (-not $authenticatorConfig) {
            try {
                $testPolicy = Get-MgPolicyAuthenticationMethodPolicy -Property Id -ErrorAction Stop
                $evidence += "`nPermission test: Basic policy access works, but specific configuration is not accessible"
            }
            catch {
                $evidence += "`nPermission test failed: Insufficient permissions to read authentication policies"
                
                return [PSCustomObject]@{
                    Control = $controlTitle
                    ControlDescription = $controlDescription
                    Finding = "Unable to assess Microsoft Authenticator configuration due to insufficient permissions."
                    Result = "INFORMATION NEEDED"
                    Evidence = $evidence + "`n`nRequired permissions: Policy.Read.All or Policy.ReadWrite.AuthenticationMethod"
                    RemediationSteps = @"
<p>To assess this control, you need additional permissions:</p>
<ol>
    <li>Ensure your account has one of the following roles:
        <ul>
            <li>Global Administrator</li>
            <li>Conditional Access Administrator</li>
            <li>Authentication Policy Administrator</li>
        </ul>
    </li>
    <li>Or ensure the application has the following Graph API permissions:
        <ul>
            <li>Policy.Read.All</li>
            <li>Policy.ReadWrite.AuthenticationMethod</li>
        </ul>
    </li>
    <li>Re-run the assessment after obtaining proper permissions</li>
</ol>
"@
                }
            }
        }
        
        # If we still don't have the authenticator config, provide general guidance
        if (-not $authenticatorConfig) {
            $controlFinding = "Unable to retrieve Microsoft Authenticator configuration. Manual verification required."
            $controlResult = "INFORMATION NEEDED"
            
            $evidence += "`n`nManual verification steps:
1. Navigate to Microsoft Entra admin center (entra.microsoft.com)
2. Go to Protection > Authentication methods > Microsoft Authenticator
3. Check the following settings under 'Configure':
   - Require number matching for push notifications: Should be Enabled
   - Show application name in push and passwordless notifications: Should be Enabled  
   - Show geographic location in push and passwordless notifications: Should be Enabled"
            
            $remediationSteps = @"
<p>Since automatic assessment is not possible, please manually verify the configuration:</p>
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
            
            return [PSCustomObject]@{
                Control = $controlTitle
                ControlDescription = $controlDescription
                Finding = $controlFinding
                Result = $controlResult
                Evidence = $evidence
                RemediationSteps = $remediationSteps
            }
        }
        
        # If we have the configuration, analyze it
        $evidence += "`n`nMicrosoft Authenticator State: $($authenticatorConfig.State)"
        
        # Check if Microsoft Authenticator is disabled
        if ($authenticatorConfig.State -eq "disabled") {
            $controlFinding = "Microsoft Authenticator is disabled."
            $controlResult = "NOT COMPLIANT"
            
            $evidence += "`n`nMicrosoft Authenticator is currently disabled in your tenant. This means:
- Users cannot use the Microsoft Authenticator app for MFA
- Anti-MFA fatigue protections cannot be implemented
- The organization is missing out on a more secure authentication method"
            
            $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Protection > Authentication methods</strong></li>
    <li>Click on <strong>Microsoft Authenticator</strong></li>
    <li>Set the state to <strong>Enabled</strong></li>
    <li>Configure the target users (e.g., All users or specific groups)</li>
    <li>Under <strong>Configure</strong>, enable all anti-MFA fatigue settings:
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
        else {
            # Microsoft Authenticator is enabled, check for MFA fatigue resistance settings
            $featureSettings = $null
            $numberMatchingEnabled = $false
            $locationInfoEnabled = $false
            $appInfoEnabled = $false
            
            # Try to get feature settings from different possible locations
            if ($authenticatorConfig.AdditionalProperties.featureSettings) {
                $featureSettings = $authenticatorConfig.AdditionalProperties.featureSettings
            } elseif ($authenticatorConfig.featureSettings) {
                $featureSettings = $authenticatorConfig.featureSettings
            }
            
            if ($featureSettings) {
                $evidence += "`n`nFeature settings found in configuration"
                
                # Check number matching
                if ($featureSettings.numberMatchingRequiredState) {
                    $numberMatchingEnabled = $featureSettings.numberMatchingRequiredState.State -eq "enabled"
                    $evidence += "`nNumber Matching Required: $($featureSettings.numberMatchingRequiredState.State)"
                }
                
                # Check location information
                if ($featureSettings.displayLocationInformationRequiredState) {
                    $locationInfoEnabled = $featureSettings.displayLocationInformationRequiredState.State -eq "enabled"
                    $evidence += "`nDisplay Location Information: $($featureSettings.displayLocationInformationRequiredState.State)"
                }
                
                # Check application information
                if ($featureSettings.displayAppInformationRequiredState) {
                    $appInfoEnabled = $featureSettings.displayAppInformationRequiredState.State -eq "enabled"
                    $evidence += "`nDisplay Application Information: $($featureSettings.displayAppInformationRequiredState.State)"
                }
            } else {
                $evidence += "`n`nFeature settings not found in configuration. This may indicate:
- The settings are configured differently than expected
- Additional permissions are required to view detailed settings
- The tenant may be using default settings"
            }

            # Evaluate compliance based on available information
            if ($numberMatchingEnabled -and $locationInfoEnabled -and $appInfoEnabled) {
                $controlFinding = "Microsoft Authenticator is configured to be resistant to MFA fatigue."
                $controlResult = "COMPLIANT"
                
                $evidence += "`n`nAll three recommended anti-MFA fatigue settings are properly enabled:
1. Number matching provides a verification code that users must enter, preventing automatic approvals
2. Location information helps users identify if a sign-in attempt is coming from an unexpected location
3. Application information helps users know which application the sign-in is for"
            } 
            elseif ($featureSettings) {
                $controlFinding = "Microsoft Authenticator is not fully configured to be resistant to MFA fatigue."
                $controlResult = "NOT COMPLIANT"
                
                $evidence += "`n`nThe following anti-MFA fatigue settings need attention:"
                
                if (-not $numberMatchingEnabled) {
                    $evidence += "`n- Number matching is not enabled (critical for preventing automated approvals)"
                }
                
                if (-not $locationInfoEnabled) {
                    $evidence += "`n- Location information is not displayed (useful for identifying suspicious sign-ins)"
                }
                
                if (-not $appInfoEnabled) {
                    $evidence += "`n- Application information is not displayed (helps users identify what they're signing into)"
                }
                
                $remediationSteps = @"
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Protection > Authentication methods</strong></li>
    <li>Click on <strong>Microsoft Authenticator</strong></li>
    <li>Under <strong>Configure</strong>, enable the missing anti-MFA fatigue settings:
        <ul>
            <li>Set <strong>Require number matching for push notifications</strong> to <strong>Enabled</strong></li>
            <li>Set <strong>Show app name in push and passwordless notifications</strong> to <strong>Enabled</strong></li>
            <li>Set <strong>Show geographic location in push and passwordless notifications</strong> to <strong>Enabled</strong></li>
        </ul>
    </li>
    <li>Click <strong>Save</strong> to apply the changes</li>
</ol>
"@
            } else {
                $controlFinding = "Microsoft Authenticator is enabled but detailed anti-fatigue settings cannot be verified."
                $controlResult = "INFORMATION NEEDED"
                
                $evidence += "`n`nMicrosoft Authenticator is enabled, but the detailed feature settings cannot be automatically verified. Manual verification is recommended."
                
                $remediationSteps = @"
<p>Manual verification is required:</p>
<ol>
    <li>Navigate to the Microsoft Entra admin center at <a href="https://entra.microsoft.com" target="_blank">https://entra.microsoft.com</a></li>
    <li>Go to <strong>Protection > Authentication methods</strong></li>
    <li>Click on <strong>Microsoft Authenticator</strong></li>
    <li>Verify that all three anti-MFA fatigue settings are enabled:
        <ul>
            <li><strong>Require number matching for push notifications</strong> should be <strong>Enabled</strong></li>
            <li><strong>Show app name in push and passwordless notifications</strong> should be <strong>Enabled</strong></li>
            <li><strong>Show geographic location in push and passwordless notifications</strong> should be <strong>Enabled</strong></li>
        </ul>
    </li>
    <li>If any settings are disabled, enable them and click <strong>Save</strong></li>
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
    }
    catch {
        return [PSCustomObject]@{
            Control = $controlTitle
            ControlDescription = $controlDescription
            Finding = "Error occurred while checking Microsoft Authenticator configuration: $_"
            Result = "ERROR"
            Evidence = "An error occurred during the assessment: $($_.Exception.Message)"
            RemediationSteps = "Please check your permissions and try running the assessment again. You may need Policy.Read.All or Policy.ReadWrite.AuthenticationMethod permissions."
        }
    }
}

# Call the function
Check-MicrosoftAuthenticatorFatigue