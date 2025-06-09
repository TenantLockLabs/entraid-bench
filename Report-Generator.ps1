function ConvertTo-HTMLReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Results,
        
        [Parameter(Mandatory = $false)]
        [string]$ReportTitle = "Microsoft Entra ID Security Assessment Report",
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "EntraID_Security_Report.html"
    )
    
    # Get the current date and time
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $tenantInfo = Get-MgOrganization | Select-Object DisplayName, Id
    
    # Calculate compliance statistics
    $totalControls = $Results.Count
    $compliantControls = ($Results | Where-Object { $_.Result -eq "COMPLIANT" }).Count
    $partiallyCompliantControls = ($Results | Where-Object { $_.Result -eq "PARTIALLY COMPLIANT" }).Count
    $informationNeededControls = ($Results | Where-Object { $_.Result -eq "INFORMATION NEEDED" -or $_.Result -eq "NOT APPLICABLE" }).Count
    $nonCompliantControls = $totalControls - $compliantControls - $partiallyCompliantControls - $informationNeededControls
    $assessableControls = $totalControls - $informationNeededControls
    if ($assessableControls -gt 0) {
        $compliancePercentage = [math]::Round(($compliantControls / $assessableControls) * 100, 2)
    } else {
        $compliancePercentage = 0
    }
    
    # Define CSS styles
    $css = @"
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f9f9f9;
            color: #333;
        }
        .container {
            width: 95%;
            margin: 20px auto;
        }
        .header {
            background-color: #0078d4;
            color: white;
            padding: 20px;
            border-radius: 5px 5px 0 0;
        }
        .tenant-info {
            background-color: #f0f0f0;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            border-left: 5px solid #0078d4;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .summary-box {
            flex: 1;
            padding: 15px;
            border-radius: 5px;
            margin: 0 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .total {
            background-color: #e6f7ff;
            border-left: 5px solid #0078d4;
        }
        .compliant {
            background-color: #ecf9ec;
            border-left: 5px solid #107c10;
        }
        .partially-compliant {
            background-color: #fff8e6;
            border-left: 5px solid #ffb900;
        }
        .non-compliant {
            background-color: #fef0f0;
            border-left: 5px solid #d13438;
        }
        .information-needed {
            background-color: #e6f9f9;
            border-left: 5px solid #00b7c3;
        }
        .controls {
            margin-top: 20px;
        }
        .control-item {
            background-color: white;
            border-radius: 5px;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .control-header {
            padding: 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .control-header h3 {
            margin: 0;
            font-size: 16px;
        }
        .control-content {
            padding: 0 15px 15px 15px;
            display: none;
            border-top: 1px solid #eee;
        }
        .status-badge {
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-compliant {
            background-color: #dff6dd;
            color: #107c10;
        }
        .status-partially-compliant {
            background-color: #fff8e6;
            color: #7a6400;
        }
        .status-non-compliant {
            background-color: #fde7e9;
            color: #d13438;
        }
        .status-information-needed {
            background-color: #e6f9f9;
            color: #00b7c3;
        }
        .status-not-applicable {
            background-color: #f0f0f0;
            color: #666666;
        }
        .status-error {
            background-color: #ffe6e6;
            color: #cc0000;
        }
        .evidence-box {
            background-color: #f9f9f9;
            padding: 10px;
            border-radius: 3px;
            margin-top: 10px;
            border-left: 3px solid #ccc;
            font-family: Consolas, monospace;
            font-size: 13px;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .recommendation {
            margin-top: 15px;
            padding: 10px;
            background-color: #e6f7ff;
            border-radius: 3px;
            border-left: 3px solid #0078d4;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .affected-accounts {
            margin-top: 10px;
        }
        .chart-container {
            display: flex;
            justify-content: center;
            margin: 20px 0;
        }
        .toggle-all {
            margin-bottom: 15px;
            background-color: #0078d4;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 3px;
            cursor: pointer;
        }
        .toggle-all:hover {
            background-color: #106ebe;
        }
        .toggle-control {
            color: #0078d4;
            text-decoration: none;
            font-weight: bold;
            font-size: 14px;
        }
        .remediation-steps {
            margin-top: 10px;
            padding: 10px;
            background-color: #fff8e6;
            border-radius: 3px;
            border-left: 3px solid #ffb900;
        }
        .remediation-steps h4 {
            margin-top: 0;
            color: #7a6400;
        }
        .control-filters {
            margin: 20px 0;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .filter-button {
            border: none;
            padding: 8px 15px;
            border-radius: 3px;
            cursor: pointer;
            background-color: #f0f0f0;
            color: #333;
        }
        .filter-button:hover {
            background-color: #e0e0e0;
        }
        .filter-button.active {
            background-color: #0078d4;
            color: white;
        }
    </style>
"@
    
    # Define JavaScript functions
    $javascript = @"
    <script>
        function toggleControl(id) {
            var content = document.getElementById('control-content-' + id);
            if (content.style.display === 'block') {
                content.style.display = 'none';
            } else {
                content.style.display = 'block';
            }
        }
        
        function toggleAllControls() {
            var contents = document.getElementsByClassName('control-content');
            var allHidden = true;
            
            for (var i = 0; i < contents.length; i++) {
                if (contents[i].style.display === 'block') {
                    allHidden = false;
                    break;
                }
            }
            
            for (var i = 0; i < contents.length; i++) {
                contents[i].style.display = allHidden ? 'block' : 'none';
            }
            
            document.getElementById('toggle-text').innerText = allHidden ? 'Collapse All' : 'Expand All';
        }
        
        function filterControls(status) {
            // Update active filter button
            var filterButtons = document.getElementsByClassName('filter-button');
            for (var i = 0; i < filterButtons.length; i++) {
                filterButtons[i].classList.remove('active');
            }
            document.getElementById('filter-' + status).classList.add('active');
            
            // Show/hide controls based on filter
            var controls = document.getElementsByClassName('control-item');
            for (var i = 0; i < controls.length; i++) {
                if (status === 'all' || controls[i].getAttribute('data-status') === status) {
                    controls[i].style.display = 'block';
                } else {
                    controls[i].style.display = 'none';
                }
            }
        }
        
        window.onload = function() {
            // Create the pie chart
            createComplianceChart($compliancePercentage);
        }
        
        function createComplianceChart(compliancePercentage) {
            var canvas = document.getElementById('compliance-chart');
            var ctx = canvas.getContext('2d');
            var centerX = canvas.width / 2;
            var centerY = canvas.height / 2;
            var radius = Math.min(centerX, centerY) - 10;
            
            // Draw the background circle
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI, false);
            ctx.fillStyle = '#f2f2f2';
            ctx.fill();
            
            // Draw the compliance percentage arc
            var startAngle = -0.5 * Math.PI;
            var endAngle = startAngle + (compliancePercentage / 100) * (2 * Math.PI);
            
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, startAngle, endAngle, false);
            ctx.lineTo(centerX, centerY);
            ctx.fillStyle = compliancePercentage >= 70 ? '#107c10' : (compliancePercentage >= 40 ? '#ffb900' : '#d13438');
            ctx.fill();
            
            // Draw the inner circle
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius * 0.7, 0, 2 * Math.PI, false);
            ctx.fillStyle = 'white';
            ctx.fill();
            
            // Draw the text
            ctx.font = 'bold 24px Arial';
            ctx.fillStyle = '#333';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(compliancePercentage + '%', centerX, centerY);
        }
    </script>
"@
    
    # Create HTML content
    $html = @"
    <!DOCTYPE html>
    <html>
    <head>
        <title>$ReportTitle</title>
        $css
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>$ReportTitle</h1>
                <p>Generated on: $reportDate</p>
            </div>
            
            <div class="tenant-info">
                <h2>Tenant Information</h2>
                <p><strong>Tenant Name:</strong> $($tenantInfo.DisplayName)</p>
                <p><strong>Tenant ID:</strong> $($tenantInfo.Id)</p>
            </div>
            
            <div class="chart-container">
                <canvas id="compliance-chart" width="200" height="200"></canvas>
            </div>
            
            <div class="summary">
                <div class="summary-box total">
                    <h2>Total Controls</h2>
                    <p>$totalControls</p>
                </div>
                <div class="summary-box compliant">
                    <h2>Compliant</h2>
                    <p>$compliantControls</p>
                </div>
"@

    if ($partiallyCompliantControls -gt 0) {
        $html += @"
                <div class="summary-box partially-compliant">
                    <h2>Partially Compliant</h2>
                    <p>$partiallyCompliantControls</p>
                </div>
"@
    }

    $html += @"
                <div class="summary-box non-compliant">
                    <h2>Non-Compliant</h2>
                    <p>$nonCompliantControls</p>
                </div>
"@

    if ($informationNeededControls -gt 0) {
        $html += @"
                <div class="summary-box information-needed">
                    <h2>Info Needed</h2>
                    <p>$informationNeededControls</p>
                </div>
"@
    }

    $html += @"
            </div>
            
            <div class="controls">
                <button class="toggle-all" onclick="toggleAllControls()">
                    <span id="toggle-text">Expand All</span>
                </button>
                
                <div class="control-filters">
                    <button id="filter-all" class="filter-button active" onclick="filterControls('all')">All Controls</button>
                    <button id="filter-compliant" class="filter-button" onclick="filterControls('compliant')">Compliant</button>
                    <button id="filter-partially-compliant" class="filter-button" onclick="filterControls('partially-compliant')">Partially Compliant</button>
                    <button id="filter-non-compliant" class="filter-button" onclick="filterControls('non-compliant')">Non-Compliant</button>
                    <button id="filter-information-needed" class="filter-button" onclick="filterControls('information-needed')">Information Needed</button>
                </div>
                
                <h2>Control Assessment Results</h2>
"@
    
    # Add each control to the HTML with FULL DETAILS
    for ($i = 0; $i -lt $Results.Count; $i++) {
        $control = $Results[$i]
        $status = $control.Result
        $statusClass = switch ($status) {
            "COMPLIANT" { "status-compliant"; $dataStatus = "compliant" }
            "PARTIALLY COMPLIANT" { "status-partially-compliant"; $dataStatus = "partially-compliant" }
            "NOT COMPLIANT" { "status-non-compliant"; $dataStatus = "non-compliant" }
            "INFORMATION NEEDED" { "status-information-needed"; $dataStatus = "information-needed" }
            "NOT APPLICABLE" { "status-not-applicable"; $dataStatus = "information-needed" }
            "ERROR" { "status-error"; $dataStatus = "non-compliant" }
            default { "status-non-compliant"; $dataStatus = "non-compliant" }
        }
        
        $html += @"
                <div class="control-item" data-status="$dataStatus">
                    <div class="control-header" onclick="toggleControl($i)">
                        <h3>$($control.Control)</h3>
                        <span class="status-badge $statusClass">$status</span>
                    </div>
                    <div id="control-content-$i" class="control-content">
                        <p><strong>Description:</strong> $($control.ControlDescription)</p>
                        <p><strong>Finding:</strong> $($control.Finding)</p>
"@
        
        # Add supporting evidence if available
        if ($control.Evidence) {
            $html += @"
                        <div class="evidence-box">
                            <strong>Supporting Evidence:</strong><br>
                            $($control.Evidence)
                        </div>
"@
        }
        
        # Add affected accounts table if available
        if ($control.AffectedAccounts -and $control.AffectedAccounts.Count -gt 0) {
            $html += @"
                        <div class="affected-accounts">
                            <h4>Affected Accounts:</h4>
                            <table>
                                <tr>
                                    <th>Name</th>
                                    <th>ID</th>
                                    <th>Details</th>
                                </tr>
"@
            
            # Limit to first 20 accounts for display performance
            $displayAccounts = $control.AffectedAccounts | Select-Object -First 20
            foreach ($account in $displayAccounts) {
                $html += @"
                                <tr>
                                    <td>$($account.Name)</td>
                                    <td>$($account.Id)</td>
                                    <td>$($account.Details)</td>
                                </tr>
"@
            }
            
            if ($control.AffectedAccounts.Count -gt 20) {
                $html += @"
                                <tr>
                                    <td colspan="3"><em>... and $($control.AffectedAccounts.Count - 20) more accounts (see CSV file for complete list)</em></td>
                                </tr>
"@
            }
            
            $html += @"
                            </table>
                        </div>
"@
        }
        
        # Add remediation steps for non-compliant controls
        if (($status -eq "NOT COMPLIANT" -or $status -eq "PARTIALLY COMPLIANT" -or $status -eq "INFORMATION NEEDED") -and $control.RemediationSteps) {
            $html += @"
                        <div class="remediation-steps">
                            <h4>Remediation Steps:</h4>
                            $($control.RemediationSteps)
                        </div>
"@
        }
        
        $html += @"
                    </div>
                </div>
"@
    }
    
    # Close HTML tags
    $html += @"
            </div>
        </div>
        $javascript
    </body>
    </html>
"@
    
    # Write the HTML to a file
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host "HTML report generated successfully at: $OutputPath" -ForegroundColor Green
    return $OutputPath
}