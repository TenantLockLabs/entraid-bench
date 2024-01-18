# entraid-bench: Microsoft Entra ID Security Assessment Tool

## Overview

The EntraID Bench is a PowerShell script designed to assess and enhance the security of your Microsoft Entra ID environment using the Graph API. It automates security checks to ensure compliance with CIS Microsoft 365 Foundations Benchmark 3.0.0.

## Features

- **Multiple Control Execution:** Efficiently assess various security aspects in a single run.
- **Result Export:** Generate CSV files for detailed analysis and reporting.
- **Modular Design:** Easily customizable to meet specific security requirements.


## Requirements

- PowerShell 5.1 or later
- [Microsoft Graph PowerShell module](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0) 
- Entra ID permissions for required Graph API calls:

```
'UserAuthenticationMethod.Read.All',
'User.Read.All',
'SecurityEvents.Read.All',
'Policy.Read.All',
'RoleManagement.Read.All',
'AccessReview.Read.All'
```

## Usage

1. Clone this repository to your local machine.
2. Run the main script: `.\entraid_scanner.ps1`
3. Review results in generated CSV files.

## Controls

- Ensure 'Phishing-resistant MFA strength' is required for Administrators
- Ensure custom banned passwords lists are used
- Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'
- Ensure a dynamic group for guest users is created
- Ensure Microsoft Authenticator is configured to protect against MFA fatigue
- Ensure that password hash sync is enabled for hybrid deployments
- Ensure 'Privileged Identity Management' is used to manage roles
- Ensure Security Defaults is disabled on Azure Active Directory
- Enable Azure AD Identity Protection user risk policies
- Ensure the admin consent workflow is enabled
- Ensure 'Microsoft Azure Management' is limited to administrative roles
- Ensure 'LinkedIn account connections' is disabled
- Ensure password protection is enabled for on-prem Active Directory
- Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users
- Ensure third party integrated applications are not allowed
- Ensure user consent to apps accessing company data on their behalf is not allowed
- Enable Conditional Access policies to block legacy authentication
- Ensure 'Self service password reset enabled' is set to 'All'
- Enable Azure AD Identity Protection sign-in risk policies
- Ensure multifactor authentication is enabled for all users in administrative roles
- Ensure multifactor authentication is enabled for all users

## Contributing

Feel free to contribute, report issues, or suggest enhancements by opening an issue.

***REMOVED***

***REMOVED***

Thank you for using the Entra ID Security Assessment Tool!

