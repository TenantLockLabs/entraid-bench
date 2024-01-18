Write-Host @"

_____       _               ___ ____    ____                  _     
| ____|_ __ | |_ _ __ __ _  |_ _|  _ \  | __ )  ___ _ __   ___| |__  
|  _| | '_ \| __| '__/ _` |  | || | | | |  _ \ / _ \ '_ \ / __| '_ \ 
| |___| | | | |_| | | (_| |  | || |_| | | |_) |  __/ | | | (__| | | |
|_____|_| |_|\__|_|  \__,_| |___|____/  |____/ \___|_| |_|\___|_| |_|



"@

# Install required AzureAD module
if (Get-Module -ListAvailable -Name Microsoft.Graph) {
    Write-Host "`nMicrosoft.Graph module is already installed." -ForegroundColor Green
} else {
    Write-Host "`nAInstalling Microsoft.Graph module..." -ForegroundColor Cyan
    Install-Module -Name Microsoft.Graph -Scope CurrentUser
}

# Function to connect to Graph with connection check
function Connect-ToGraph {
    if (Get-MgContext) {
      Write-Host "`nAlready connected to Microsoft Graph." -ForegroundColor Green
    } else {
      Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
      try {
        Connect-MgGraph -Scopes @(
          'UserAuthenticationMethod.Read.All',
          'User.Read.All',
          'SecurityEvents.Read.All',
          'Policy.Read.All',
          'RoleManagement.Read.All',
          'AccessReview.Read.All'
        )
        Write-Host "`nConnected successfully." -ForegroundColor Green
      } catch {
        Write-Error "Error connecting to Graph: $_"
      }
    }
  }
  
Connect-ToGraph

Write-Host "`nExecuting the Microsoft Entra ID Security Assessment Tool..." -ForegroundColor Green

# Specify the path to your script files
$scriptPath = "./controls"  # Replace with the actual path

# List available function names
$functionNames = Get-ChildItem -Path $scriptPath -Filter *.ps1 | ForEach-Object { $_.BaseName }

# Map control file names to titles
$functionTitleMappings = @{
    "Check-authenticationStrength" = "Ensure 'Phishing-resistant MFA strength' is required for Administrators"
    "Check-BannedPasswords" = "Ensure custom banned passwords lists are used"
    "Check-BlockNonAdminTenantCreation" = "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"
    "Check-DynamicGroupForGuestUsers" = "Ensure a dynamic group for guest users is created"
    "Check-MicrosoftAuthenticatorFatigue" = "Ensure Microsoft Authenticator is configured to protect against MFA fatigue"
    "Check-OnPremisesSync" = "Ensure that password hash sync is enabled for hybrid deployments"
    "Check-PermanentActiveAssignments" = "Ensure 'Privileged Identity Management' is used to manage roles"
    "Check-SecurityDefaultStatus" = "Ensure Security Defaults is disabled on Azure Active Directory"
}

# Initialize progress bar parameters
$totalControls = $functionNames.Count
$completedControls = 0


# Validate and execute the chosen function(s)
    $allResults = @()

    foreach ($functionName in $functionNames) {
        $functionTitle = $functionTitleMappings[$functionName]

            # Update progress bar
            $completedControls++
            # Clear previous progress bar line
            Write-Host "`r" -NoNewline
            # Create a simple progress bar using characters
            $progressBar = '=' * $completedControls + ' ' * (21 - $completedControls)
            Write-Host "Checking Control: $progressBar ($completedControls of 21): $functionTitle"

        $currentResults = . "$scriptPath\$functionName.ps1" | Select Control, ControlDescription, Finding, OnPremisesSyncEnabled, LastSyncDateTime, DynamicGroupName, DynamicGroupTypes, DynamicGroupMembershipRule, Result
        $allResults += $currentResults  # Append results to the array
        
    }

    $allResults | Export-Csv -Path "scan_results.csv" -NoTypeInformation
    Write-Host "`nScript execution complete! All results combined and exported to scan_results.csv." -ForegroundColor Green