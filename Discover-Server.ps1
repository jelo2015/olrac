# requires -version 3
########################################################################
# Program Name: Discover-Server
# Description: Scan a subnet to check for server access
# Author: Paolo Hernandez (phernandez5@csc.com)
# Version: 1.0
# Completion Date: 11/16/2017
########################################################################

$style = @"
<style>
h1, h5, th { text-align: center; }
table { margin-left:auto; margin-right:auto; font-family: Segoe UI; box-shadow: 10px 10px 5px #888; border: thin ridge grey; }
th { background: #0046c3; color: #fff; max-width: 400px; padding: 5px 10px; }
td { font-size: 11px; padding: 5px 20px; color: #000; }
tr { background: #b8d1f3; }
tr:nth-child(even) { background: #dae5f4; }
tr:nth-child(odd) { background: #b8d1f3; }
</style>
"@


#--Script path when compiled as an EXE
$global:scriptPath = pwd | Select-Object -ExpandProperty Path


$VerbosePreference = "Continue"
$ErrorActionPreference = "SilentlyContinue"

$global:LOGPATH = $scriptPath + '\Logs\' + 'Discover-Server_' + (Date -Format "yyyyMMddhhmmss") + '.log'
$global:EMAILLOGPATH = $scriptpath + ("\Discover-Server_emaillog_" + (date -Format "yyyyMMddhhmmss") + ".log")
$global:REPORTPATH = $scriptPath + '\Reports\' + 'Discover-Server_' + (Date -Format "yyyyMMddhhmmss") + '.html'
$global:ATT = $scriptPath + '\Attachments\' + $subnets + '-' + (Date -Format "yyyyMMddhhmmss") + '.csv'

# Supporting Functions
function Output-Message
{
    [CmdletBinding()]
    param(

    [Parameter(Position=1,
    ValueFromPipeline=$true)]
    [String]$Message,

    [Parameter(Position=2)]
    [String]$Path = $global:LOGPATH,

    [Parameter(Position=3)]
    [String]$datedisplay = (date -F {MM/dd/yyy hh:mm:ss:}),

    [Parameter(Position=4)]
    [switch]$log,

    [Parameter(Position=5)]
    [switch]$Warn,

    [Parameter(Position=6)]
    [switch]$Err,

    [Parameter(Position=7)]
    [switch]$Silent
    )

    if (($PSBoundParameters.ContainsKey('Silent')) -ne $true)
    {
        if ($PSBoundParameters.ContainsKey('Warn')) { 
            Write-warning -Message "$datedisplay [WARNING]$Message" 
            $global:encounteredWarning = $true}
        elseif ($PSBoundParameters.ContainsKey('Err')) { 
            Write-verbose "$datedisplay [ERROR]$Message" -verbose
            $global:encounteredError = $true
            }
        elseif ($PSBoundParameters.ContainsKey('Log')) { 
        Write-verbose "#    $Message    " -verbose
        }
        else { Write-verbose "$datedisplay $Message" }
    }
}

function Load-Settings
{
    
    [CmdletBinding()]
    param(
    [parameter()]
    [string]$configFile)

    $global:subnets = @()

    if (Test-Path $configFile)
    {   
        $configData = Get-Content -Path $configFile
        foreach ($line in $configData)
        {
            if ($line -ne "" -and $line -notlike "#*") {
                
                if ($line -like "*Email_To*") {
                    $global:emailto = $line.Split('=')[1]
                }
                if ($line -like "*Email_CC*") {
                    $global:emailcc = $line.Split('=')[1]
                }
                if ($line -like "*Email_From*") {
                    $global:emailfrom = $line.Split('=')[1]
                }
                if ($line -like "*Email_SMTP_Server*") {
                    $global:smtpserver = $line.Split('=')[1]
                }
                if ($line -like "*Email_SMTP_Port*") {
                    $global:smtpport = $line.Split('=')[1]
                }
                if ($line -like "*Email_Subject*") {
                    $global:emailsubject = $line.Split('=')[1]
                }
                if ($line -like "*Email_Error_Subject*") {
                    $global:emailerrorsubject = $line.Split('=')[1]
                }
                if ($line -like "*Email_Body*") {
                    $global:emailbody += $line.Split('=')[1]
                    $global:emailbody += "`n"
                }
                
                if ($line -like "*Log_History*") {
                    $global:loghistory = $line.Split('=')[1]
                }
                if ($line -like "Email_Notification*") {
                    $global:emailnotification = $line.Split('=')[1]
                }
                if ($line -like "Subnet*") {
                    $global:Subnets += $line.Split('=')[1]
                }
            }
        }
    }
    else {
        Output-Message "Missing configuration file" -Err
        return $false
    }

    return $true
}

function Clean-OldLogs
{
    [CmdletBinding()]
    param(
 
    [Parameter()]
    [string]$History = $global:logHistory
    )
    try {
        $logsList = get-childitem -Path "$scriptpath\Logs" | Sort-Object -Property 'LastWriteTime' -Descending | Select-Object -ExpandProperty Name

        if ($logsList.Count -ge $History) {
            $logCounter = 1
            foreach ($log in $logsList)
            {
                if ($logCounter -gt $History)
                {
                    Remove-Item -Path "$scriptpath\Logs\$log" -Force > $null
                }
                $logCounter++
            }
        }
              
        #return $true
    }
    catch [Exception] {
        return $_
    }
}

function Email-Result
{
    [CmdletBinding()]
    param(

    [Parameter(Position=1)]
    [string[]]$To = $global:emailto,

    [Parameter(Position=2)]
    [string]$CC = $global:emailcc,

    [Parameter(Position=3)]
    [string[]]$From = $global:emailfrom,

    [Parameter()]
    [string]$SMTPServer = $global:smtpserver,

    [Parameter()]
    [string]$SMTPPort = $global:smtpport,
       
    [Parameter()]
    [string]$Subject = $global:emailsubject,

    [Parameter()]
    [string]$Body = $global:emailbody,

    [Parameter()]
    [switch]$Error,

    [Parameter()]
    [switch]$Warning
    )
    BEGIN
    {
    }
    PROCESS
    {
        Output-Message "Creating email message"
        $SMTPmessage = New-Object Net.Mail.MailMessage($From,$To)
        foreach ($address in $CC.Split(','))
        {
            $SMTPmessage.CC.Add($address)    
        }
        $SMTPmessage.Subject = $Subject 
        $SMTPmessage.IsBodyHtml = $false
        if ($PSBoundParameters.ContainsKey('Error'))
        {
            $SMTPmessage.Priority = [System.Net.Mail.MailPriority]::High
            $SMTPmessage.Subject = $global:emailerrorsubject
        }
        # Compose email body
        $EmailBody = Get-Content "$global:ReportPath"
        
        #Attach csv file        
        $Attached_csv = new-object Net.Mail.Attachment($global:ATT)
        $SMTPmessage.Attachments.Add($Attached_csv)        

        ## End email body composition
        $SMTPmessage.IsBodyHtml = $true
        $SMTPmessage.Body = $EmailBody
        Output-Message "Email message created"

        $SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer,$SMTPPort)
        try
        {
            Output-Message "Sending email message..."
            $SMTPClient.Send($SMTPmessage)
            Output-Message "Email sent!"
            #return $true
        }
        catch [Exception]
        {
            Output-Message "Unable to send email" -err
            #return $_
        }
    }
    END
    {
        
        $Attached_csv.Dispose()
        $SMTPmessage.Dispose()
        #Remove-Item "$global:EMAILLOGPATH" -force -ea SilentlyContinue
    }
}

function Discover-Server{
    Begin{
        $configs = Get-Childitem $scriptpath -Filter "*config*.ini" | Select-Object -ExpandProperty Fullname
    }
    Process{
        foreach ($config in $configs){

            $load = Load-Settings -configFile "$config"

            if ($load -eq $true){
                Output-Message "Configuration successfully loaded"

                if ($global:subnets){
                        $obj = @()
                        $networksubnet = @()
                        

                    foreach ($subnet in $global:subnets){
                        $wholesubnet = 1..255 | % {"$subnet.$_"}
                        $networksubnet += $wholesubnet
                        $servers = @()

                        
                        }
                        Output-Message "Processing subnet" 
                        

                        foreach($IP in $networksubnet){                            

                            Output-Message "IP: $IP"
                            

                            if(Test-Connection -count 1 -comp $IP -quiet) {
                                
                                # get hostname
                                try { 
                                    $hostname = (Get-WmiObject -Class Win32_ComputerSystem -computername "$IP" -Property Name -ea stop).Name
                                    if ($hostname){
                                        $IPAddress = $IPAddress = Get-WmiObject -Class win32_networkadapterConfiguration -filter "ipenabled='True'" -ComputerName "$IP" -ea stop | where {$_.IPAddress -notlike "10.*"} |Select-Object -ExpandProperty IPAddress
                                        $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName "$IP" -ea stop | Select-Object -ExpandProperty Caption
                                        #$monsu = Get-WmiObject win32_useraccount -ComputerName "$IP" -Filter "LocalAccount=True" -ea Stop | where {$_.name -eq "monsu"}
                                    }    
                                }
                                catch {
                                    Output-Message "$($_)" -warn
                                }

                                        
                                            if ($hostname){
                                              

                                                if ($servers -notcontains $hostname){
                                        
                                                    $props = [ordered]@{
                                                        'Server Name'=$hostname
                                                        'IP Address'= "$IPAddress"                                                        
                                                        'Operating System'=$OS
                                                        
                                                        }
                                                    $obj += @(New-Object pscustomobject -Property $props)
                                                    $obj | Export-Csv -Path $global:ATT -NoTypeInformation
                                        
                                                    Output-Message "Server: $hostname successfully added"
                                                    $servers += $hostname
                                                    $count = ($servers | measure).count

                                                    
                                        
                                                }
                                            
                                    
                                 }                                
                            }    
                        }

                        # format to html
                        if ($obj){                                
                                   
                            ConvertTo-Html -Head "$style" -Title "$subnets" -Body "<h1>$subnets</h1>" | Add-content -path "$global:reportPath"                                                  
                            $obj | Select-Object "Server Name","IP Address","Operating System" | Sort-Object 'Server Name' | ConvertTo-Html -Head "$style" -Body "<strong><h5>$(get-date -format "MM/dd/yyyy")</h5></strong>" | Add-content -path "$global:reportPath"
                            ConvertTo-Html -Body "<p><font face=Calibri><font color=darkgreen>Number of Servers: </font><strong><font color=blue>$count</strong></font></font></p>" | Add-content -path "$global:reportPath" 
                             
                        }
                    }

                    
                        
                            
                
                else {
                    Output-Message "Empty subnets" -err
                }
            }
            else{
                Output-Message "Configuration failed" -err
            }

        } # foreach config
    }
    End{
        if ($global:encounteredError -eq $true){
            Email-Result -Error
        }
        else{
            Email-Result
        }
    }
}

Discover-Server *>&1 | Tee -FilePath $global:LOGPATH -append