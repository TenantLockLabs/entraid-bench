# entraid-bench: Enhanced Microsoft Entra ID Security Assessment Tool

![Enhanced Entra ID Security Assessment Tool](screenshot.png)

## Overview

The **Enhanced Entra ID Security Assessment Tool** is a comprehensive PowerShell-based solution that provides enterprise-grade security assessment of Microsoft Entra ID environments. Built on the Microsoft Graph API, this tool automates security checks based on the **CIS Microsoft 365 Foundations Benchmark 3.0.0** and delivers professional HTML reports with detailed evidence collection and step-by-step remediation guidance.

## 🚀 Key Features

### **Comprehensive Security Assessment**
- **25+ Security Controls** covering critical Entra ID configurations
- **CIS Benchmark Compliance** aligned with Microsoft 365 Foundations Benchmark 3.0.0
- **License-Aware Assessment** automatically detects Entra ID P2/Governance capabilities
- **PowerShell 5.1+ Compatible** works across Windows PowerShell and PowerShell Core

### **Professional Reporting**
- **Interactive HTML Reports** with expandable controls and visual compliance charts
- **Executive Dashboard** with overall compliance percentage and control breakdown
- **Evidence Collection** with detailed supporting data and affected accounts
- **Multiple Export Formats** (HTML, CSV, individual evidence files)

### **Enhanced User Experience**
- **Real-Time Progress Tracking** with detailed status updates
- **Intelligent Error Handling** with graceful degradation and clear guidance
- **Automated Permission Detection** adapts to available Graph API permissions
- **Manual Verification Guidance** when automated assessment isn't possible

### **Enterprise-Grade Capabilities**
- **Remediation Guidance** with step-by-step HTML-formatted instructions
- **Evidence Documentation** suitable for compliance audits and security reviews
- **Affected Account Tracking** identifies specific users requiring attention
- **Risk Assessment** with color-coded compliance indicators

## 📋 Requirements

### **Environment Requirements**
- **PowerShell:** 5.1 or later (Windows PowerShell or PowerShell Core)
- **Operating System:** Windows 10/11, Windows Server 2016+, or cross-platform with PowerShell Core
- **Internet Connectivity:** Access to Microsoft Graph endpoints

### **Microsoft Graph Permissions**
The tool automatically requests the following permissions:

#### **Core Permissions (Required)**
```powershell
'User.Read.All'                           # Read user profiles and authentication methods
'Directory.Read.All'                      # Read directory objects and settings
'Policy.Read.All'                         # Read security and compliance policies
'Group.Read.All'                          # Read group configurations
```

#### **Enhanced Assessment Permissions (Recommended)**
```powershell
'UserAuthenticationMethod.Read.All'      # Read MFA and authentication configurations
'RoleManagement.Read.All'                # Read role assignments and PIM settings
'Policy.ReadWrite.AuthenticationMethod'  # Read detailed authentication policies
'IdentityProvider.Read.All'               # Read external identity providers
'Application.Read.All'                    # Read application and service principal configs
'SecurityEvents.Read.All'                # Read security events and risk data
'AccessReview.Read.All'                   # Read access review configurations
'IdentityRiskEvent.Read.All'              # Read Identity Protection risk events
```

### **Administrative Requirements**
- **Entra ID Role:** Global Reader (minimum), Global Administrator (recommended for full assessment)
- **Licensing:** Some advanced features require Entra ID P2 or Governance licenses

## 🛠️ Installation & Usage

### **Quick Start**
```powershell
# 1. Clone the repository
git clone https://github.com/your-username/entraid-bench.git
cd entraid-bench

# 2. Run the assessment (module will be installed automatically)
.\entraid_scanner.ps1

# 3. Review the generated HTML report (opens automatically)
```

### **Manual Module Installation** (if needed)
```powershell
# Install Microsoft Graph PowerShell module
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force

# Import required modules
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.DirectoryManagement
```

### **Advanced Usage**
```powershell
# Run with specific authentication (for automation)
Connect-MgGraph -ClientId "your-app-id" -TenantId "your-tenant-id" -CertificateThumbprint "cert-thumbprint"
.\entraid_scanner.ps1

# Run specific controls only (modify the controls folder)
.\entraid_scanner.ps1
```

## 🔍 Security Controls Assessed

### **Authentication & Multi-Factor Authentication**
| Control | Description | License Requirement |
|---------|-------------|-------------------|
| ✅ **Phishing-Resistant MFA for Admins** | Ensures administrators use phishing-resistant authentication methods | Any |
| ✅ **Microsoft Authenticator Anti-Fatigue** | Validates number matching and context information settings | Any |
| ✅ **MFA for All Users** | Verifies multi-factor authentication for all user accounts | Any |
| ✅ **MFA for Administrative Roles** | Ensures privileged accounts have MFA enabled | Any |
| ✅ **Legacy Authentication Blocking** | Confirms legacy authentication protocols are disabled | Any |

### **Identity Protection & Risk Management**
| Control | Description | License Requirement |
|---------|-------------|-------------------|
| ✅ **User Risk Policies** | Validates automated response to risky user behavior | Entra ID P2 |
| ✅ **Sign-in Risk Policies** | Checks automated response to risky sign-in attempts | Entra ID P2 |
| ✅ **Emergency Access Accounts** | Verifies break glass account configuration | Any |
| ✅ **External Identity Settings** | Reviews guest user and B2B collaboration security | Any |

### **Privileged Access Management**
| Control | Description | License Requirement |
|---------|-------------|-------------------|
| ✅ **Privileged Identity Management** | Ensures PIM is used for privileged role assignments | Entra ID P2 |
| ✅ **Admin Consent Workflow** | Validates application consent governance | Any |
| ✅ **Tenant Creation Restrictions** | Confirms non-admins cannot create new tenants | Any |
| ✅ **Administrative Role Limitations** | Reviews Azure Management access restrictions | Any |

### **Password & Authentication Security**
| Control | Description | License Requirement |
|---------|-------------|-------------------|
| ✅ **Custom Banned Passwords** | Validates organization-specific password restrictions | Any |
| ✅ **Security Defaults Configuration** | Ensures Security Defaults are properly configured | Any |
| ✅ **Self-Service Password Reset** | Reviews SSPR configuration and security | Any |
| ✅ **Password Hash Synchronization** | Validates hybrid deployment password sync | Any |

### **Application & Session Security**
| Control | Description | License Requirement |
|---------|-------------|-------------------|
| ✅ **Third-Party Application Controls** | Reviews external application access restrictions | Any |
| ✅ **Integrated Application Policies** | Validates internal application security settings | Any |
| ✅ **Sign-in Frequency Management** | Checks session timeout and persistence settings | Any |
| ✅ **LinkedIn Integration Controls** | Verifies LinkedIn account connection restrictions | Any |

### **Guest User & Collaboration Security**
| Control | Description | License Requirement |
|---------|-------------|-------------------|
| ✅ **Dynamic Groups for Guests** | Ensures automated guest user management | Any |
| ✅ **Guest Access Restrictions** | Reviews external user permission limitations | Any |
| ✅ **Collaboration Domain Controls** | Validates B2B collaboration domain restrictions | Any |

## 📊 Report Output

### **Generated Files**
The assessment creates several output files with timestamped names:

#### **📄 HTML Report** - `EntraID_Security_Assessment_YYYYMMDD_HHMMSS.html`
- **Interactive Dashboard** with compliance overview and visual charts
- **Expandable Control Details** with evidence and remediation steps
- **Filtering Capabilities** to view controls by compliance status
- **Professional Formatting** suitable for executive reporting

#### **📈 CSV Data Export** - `EntraID_Security_Assessment_YYYYMMDD_HHMMSS.csv`
- **Raw Assessment Data** for analysis and tracking
- **Control Names, Findings, and Compliance Status**
- **Import-friendly format** for spreadsheet analysis

#### **📁 Evidence Folder** - `Evidence_YYYYMMDD_HHMMSS/`
- **Detailed Evidence Files** for complex findings
- **Affected Accounts CSV** files with specific user details
- **Supporting Documentation** for audit and compliance purposes

### **Report Features**

#### **Executive Summary Section**
- Overall compliance percentage with color-coded indicators
- Control breakdown by compliance status
- Tenant information and assessment metadata

#### **Interactive Control Details**
- Click to expand detailed findings for each control
- Supporting evidence with technical details
- Affected accounts with specific user information
- Step-by-step remediation guidance with links to Microsoft documentation

#### **Visual Compliance Indicators**
- ✅ **COMPLIANT** - Control meets security requirements
- ⚠️ **PARTIALLY COMPLIANT** - Control partially meets requirements
- ❌ **NOT COMPLIANT** - Control does not meet security requirements
- ℹ️ **INFORMATION NEEDED** - Additional licensing or permissions required
- ❔ **NOT APPLICABLE** - Control not relevant to current configuration

## 🔧 Troubleshooting

### **Common Issues and Solutions**

#### **Permission Errors**
```powershell
# Issue: Access denied for specific controls
# Solution: Connect with enhanced permissions
Connect-MgGraph -Scopes 'Policy.Read.All', 'Policy.ReadWrite.AuthenticationMethod', 'RoleManagement.Read.All'
```

#### **Module Installation Issues**
```powershell
# Issue: Module installation fails
# Solution: Install with elevated permissions or user scope
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

#### **Filter Syntax Errors**
- **Resolved**: The tool now uses multiple targeted API calls instead of complex filters
- **Fallback**: Local filtering when Graph API filters fail
- **Impact**: Improved reliability across different tenant configurations

#### **Authentication Method Access Issues**
- **Enhanced**: Multiple API approaches with graceful degradation
- **Guidance**: Manual verification steps when automated assessment fails
- **Documentation**: Clear permission requirements and next steps

### **PowerShell Version Compatibility**
```powershell
# Check your PowerShell version
$PSVersionTable.PSVersion

# Minimum required: 5.1
# Recommended: 7.0 or later for best performance
```

## 🔒 Security & Privacy

### **Data Handling**
- **Read-Only Operations**: The tool only reads configuration data
- **No Data Storage**: No sensitive information is permanently stored
- **Local Processing**: All analysis performed locally on your machine
- **Secure Connections**: All API calls use Microsoft Graph secure endpoints

### **Generated Reports**
- **Sensitive Information**: Reports may contain organizational security details
- **Storage Recommendations**: Store reports according to your data classification policies
- **Access Control**: Limit report access to authorized security personnel
- **Retention**: Follow organizational data retention policies

## 📈 Enterprise Usage

### **Best Practices**
- **Regular Assessments**: Run monthly or quarterly assessments
- **Baseline Documentation**: Establish initial security baselines
- **Change Tracking**: Compare reports over time to track improvements
- **Exception Documentation**: Document any organizational policy exceptions

### **Compliance Integration**
- **Audit Evidence**: Use evidence files for compliance audits
- **Risk Assessment**: Leverage findings for security risk assessments
- **Remediation Tracking**: Track remediation progress over time
- **Management Reporting**: Use HTML reports for executive briefings

### **Automation Opportunities**
```powershell
# Example: Scheduled assessment with automated reporting
# Create scheduled task or Azure Automation runbook
.\entraid_scanner.ps1
Send-MailMessage -To "security-team@company.com" -Subject "Entra ID Assessment" -Attachments "EntraID_Security_Assessment_*.html"
```

## 🤝 Contributing

### **How to Contribute**
1. **Fork the Repository** and create a feature branch
2. **Add New Controls** following the existing pattern in `/controls/`
3. **Enhance Existing Controls** with additional evidence or remediation steps
4. **Update Documentation** for any new features or changes
5. **Submit Pull Request** with detailed description of changes

### **Development Guidelines**
- **PowerShell 5.1 Compatibility**: Ensure all code works on PowerShell 5.1+
- **Error Handling**: Implement comprehensive try-catch blocks
- **Evidence Collection**: Provide detailed evidence for all findings
- **Remediation Steps**: Include step-by-step HTML-formatted guidance

## 📞 Support & Resources

### **Getting Help**
- **GitHub Issues**: [Report bugs or request features](https://github.com/your-username/entraid-bench/issues)
- **LinkedIn**: [Contact the maintainer](https://www.linkedin.com/in/alaanasser00/)
- **Microsoft Documentation**: [Entra ID Security Best Practices](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults)

### **Related Resources**
- **CIS Benchmarks**: [Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365)
- **Microsoft Graph**: [PowerShell SDK Documentation](https://docs.microsoft.com/en-us/powershell/microsoftgraph/)
- **Entra ID Documentation**: [Security Best Practices](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/)

## 📜 License & Disclaimer

### **License**
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### **Important Disclaimer**
This tool provides security assessment guidance based on industry best practices and Microsoft recommendations. However, it should not replace professional security consultation or comprehensive security reviews. Always:

- **Validate Findings** against your organization's specific requirements
- **Test Changes** in a non-production environment first  
- **Consult Security Professionals** for complex security decisions
- **Follow Organizational Policies** and compliance requirements

### **Support Statement**
This is a community-driven project. While we strive for accuracy and reliability, use of this tool is at your own risk. Always verify findings and test recommendations in your specific environment.

---

**🎯 Ready to enhance your Entra ID security posture?** Clone the repository and run your first assessment today!

```powershell
git clone https://github.com/watson0x90/entraid-bench.git
cd entraid-bench
.\entraid_scanner.ps1
```