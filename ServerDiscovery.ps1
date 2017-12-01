
#--Script path when compiled as an EXE
$global:scriptPath = pwd | Select-Object -ExpandProperty Path
$global:LOGPATH = $scriptPath + '\Logs\' + 'ServerDiscovery_' + (Date -Format "yyyyMMddhhmmss") + '.log'
$global:EMAILLOGPATH = $scriptPath + '\ServerDiscovery_EmailLog_' + (Date -Format "yyyyMMddhhmmss") + '.log'
$global:Key = (3,4,2,3,56,34,254,222,1,1,2,23,42,54,33,233,1,34,2,7,6,5,35,43)


$VerbosePreference = "Continue"
$ErrorActionPreference = "Continue"

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

#-- Definition functions to decript encrypted FTP credetial
function Get-DecryptedFTPUser {
    [CmdletBinding()]
    param(
    [parameter()]
    $DecryptKey,
    
    [parameter()]
    [string]$Path
    )
 
    $ftpcred = ((Get-Content -Delimiter "," "$Path") -replace ',','')
    $ftpuser =  Decrypt-SecureString (ConvertTo-SecureString $ftpcred[0] -Key $DecryptKey)
    $ftpuser
}
 
function Get-DecryptedFTPPassword {
    [CmdletBinding()]
    param(
    [parameter()]
    $DecryptKey,
    
    [parameter()]
    [string]$Path
    )
 
    $ftpcred = ((Get-Content -Delimiter "," "$Path") -replace ',','')
    $ftppassword = Decrypt-SecureString (ConvertTo-SecureString $ftpcred[1] -Key $DecryptKey)
    $ftppassword
}
 
function Decrypt-SecureString {
    param(
    [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=0)]
    [System.Security.SecureString]$sstr
    )
 
    $marshal = [System.Runtime.InteropServices.Marshal]
    $ptr = $marshal::SecureStringToBSTR( $sstr )
    $str = $marshal::PtrToStringBSTR( $ptr )
    $marshal::ZeroFreeBSTR( $ptr )
    $str
}
 
function Get-DecryptedPKPassword
{
    [CmdletBinding()]
    param(
    [parameter()]
    $DecryptKey,
    
    [parameter()]
    [string]$Path
    )
 
    $pkcontent = Get-Content $Path
    $pkpassword = Decrypt-SecureString (ConvertTo-SecureString $pkcontent -Key $DecryptKey)
    $pkpassword
}

function Load-Settings
{
    
    [CmdletBinding()]
    param(
    [parameter()]
    [string]$configFile)

    $global:subnets = @()
    $global:encounteredError = $false
    $global:encounteredWarning = $false

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
                if ($line -like "FTP_Credential*") {
                    if ($line -like "*E:*" -or $line -like "*C:*") {
                        $ftpFilePath = $line.Split('=')[1]
                    }
                    else {
                        $ftpFilePath = $scriptpath + '\' + $line.Split('=')[1]
                    }
                    if (Test-Path $ftpFilePath)
                    {
                        $global:ftpusername = Get-DecryptedFTPUser -DecryptKey $global:Key -Path $ftpFilePath
                        $global:ftppassword = Get-DecryptedFTPPassword -DecryptKey $global:Key -Path $ftpFilePath
                    }
                    else {
                        Output-Message "FTP credential file not found"
                        return $false
                    }
                }
                if ($line -like "FTP_Server*") {
                    $global:ftpserver = $line.Split('=')[1]
                }
                if ($line -like "RemotePath*") {
                    $global:RemotePath = $line.Split('=')[1]
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
    }
    catch [Exception] {
        return $_
    }
}

function IPrange{
	param ( 
	  [string]$ip, 
	  [int]$cidr 
	) 
 
	Begin{

		function INT64-toIP() { 
			param ([int64]$int) 
			return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
		}

		function IP-toINT64 () { 
			param ($ip) 
		 	$octets = $ip.split(".") 
			return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
		}
	}

	Process{ 
	 	if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
		if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
		if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
		if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 

		 
	 
		if ($ip) { 
		  $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
		  $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
		} 
		else { 
		  $startaddr = IP-toINT64 -ip $start 
		  $endaddr = IP-toINT64 -ip $end 
		} 
	 
	 
		for ($i = $startaddr; $i -le $endaddr; $i++) { 
		  INT64-toIP -int $i 
		}
	}
	End{}	
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
    [string]$Subnet,

    [Parameter()]
    [switch]$Error
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
        $Subject = $Subject -replace '<subnet>',"$Subnet"
        $SMTPmessage.Subject = $Subject
        $SMTPmessage.IsBodyHtml = $false

        if ($PSBoundParameters.ContainsKey('Error'))
        {
            $SMTPmessage.Priority = [System.Net.Mail.MailPriority]::High
            $errorSubject = $global:emailerrorsubject
            $errorSubject = $errorSubject -replace '<subnet>',"$Subnet"
            $SMTPmessage.Subject = $errorSubject
        }
        # Compose email body
        $EmailBody += "Task: Server Discovery Discovery`n"
        $EmailBody += "Subnet: $Subnet`n"
        
        $displaydate = date -F {MM/dd/yyyy}
        $EmailBody += "Execution Date: $displaydate`n"

        $EmailBody += "Please refer to attached logs."
                
        if ($PSBoundParameters.ContainsKey('Error'))
        {
            $EmailBody += "`n[RESULT]: ERROR"
            $EmailBody += "`n          Please review the log file for details"
        }
        else
        {
            $EmailBody += "`n[RESULT]: SUCCESS"
            $EmailBody += "`n          Refer to attached log file for details."
        }

        ## End email body composition
        $SMTPmessage.Body = $EmailBody
        Output-Message "Email message created"
        Copy-Item -Path $LOGPATH -Destination $EMAILLOGPATH -Force -ErrorAction SilentlyContinue > $null
        $Attached_log = New-Object System.Net.Mail.Attachment($EMAILLOGPATH)
        $SMTPmessage.attachments.Add($Attached_log)

        $SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer,$SMTPPort)
        try
        {
            Output-Message "Sending email message..."
            $SMTPClient.Send($SMTPmessage)
            Output-Message "Email sent!"
        }
        catch [Exception]
        {
            Output-Message "Unable to send email. The error message is: $_" -err
        }
    }
    END
    {
        $Attached_log.Dispose()
        $SMTPmessage.Dispose()
        Remove-Item -Path $EMAILLOGPATH -Force -ErrorAction SilentlyContinue > $null
    }
}

function UploadTo-FTP
{
    [CmdletBinding()]
    param(
    [parameter()]
    [string]$ftpserver = "$global:ftpserver",

    [parameter()]
    [string]$ftpusername = "$global:ftpUserName",

    [parameter()]
    [string]$ftppassword = "$global:ftpPassword",

    [parameter()]
    [string]$localpath,

    [parameter()]
    [string]$remotepath = "$global:RemotePath"

    )
    BEGIN 
    {
        # Load WinSCP .NET assembly
        Output-Message "Loading WINSCP assembly"
        [Reflection.Assembly]::LoadFrom("file:////$scriptpath\Res\WinSCP\WinSCP.dll") | Out-Null
        #[Reflection.Assembly]::LoadFrom("file:////$scriptpath\Res\WinSCP\WinSCP.dll") | Out-Null
     
        # Setup session options
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
            Protocol = [WinSCP.Protocol]::ftp
            HostName = $global:ftpserver
            UserName = $global:ftpUserName
            Password = $global:ftpPassword
            FTPMode = [WinSCP.FtpMode]::Passive
        }
     
        Output-Message "Opening WINSCP session"
        $session = New-Object WinSCP.Session

        if($session){
            # Connect
            $session.Open($sessionOptions)
        }
    }

    Process
    {
        try{
            $transferResult = $session.PutFiles("$localpath","$remotepath/", $False, $transferOptions)
            $transferResult.Check()
            $name = $localpath.Split('\')[-1]
            if ($transferResult.IsSuccess){Output-Message "Upload of $name succeeded"}
            else{Output-Message "Upload of $name failed" -err} 
        }
        catch{
            Output-Message "$($_)" -err
        }
        finally{
            # Disconnect, clean up
            $session.Dispose()
        }    
       
    }
    End
    {
        return $true
    }    
}

function Main-Program{
	
	Begin{
		$configs = Get-Childitem $scriptpath -Filter "*config*.ini" | Select-Object -ExpandProperty Fullname
	}
	Process{
		foreach ($config in $configs){	
			
			$load = Load-Settings -configFile "$config"

			if ($load -eq $true){
				
				foreach ($subnet in $global:subnets){
					$servers = @()
					$obj = @()
					$ip = $subnet.Split('/')[0]
					$cidr = $subnet.Split('/')[1]
					$iprange = iprange -ip "$ip" -cidr $cidr
					
					Output-Message "Processing subnet: $subnet"

					foreach($ipaddress in $iprange){
						Output-Message "IP Address: $ipaddress"
						if(Test-Connection -count 1 -comp $ipaddress -quiet) {

							# get hostname
							try { 
								$hostname = (Get-WmiObject -Class Win32_ComputerSystem -computername "$ipaddress" -Property Name -ea stop).Name 
							}
							catch {
								Output-Message "$($_)" -warn
								$hostname = $null
							}

							if ($hostname){
								if ($servers -notcontains $hostname){	
									try { 
										$IPAddress = Get-WmiObject -Class win32_networkadapterConfiguration -filter "ipenabled='True'" -ComputerName "$ipaddress" -ea stop | 
                                        where {$_.IPAddress -notlike "10.*"} | Select-Object -ExpandProperty IPAddress
                                        $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName "$ipaddress" -ea stop | Select-Object -ExpandProperty Caption
										
                                        $props = [ordered]@{
                                        'Server Name'=$hostname
                                        'IP Address'= "$IPAddress"
                                        'Operating System'=$OS
                                        }
                                        
                                        $obj += @(New-Object pscustomobject -Property $props)
                                        Output-Message "Server: $hostname successfully added"
                                    }
									catch{
										Output-Message "$($_)" -warn
									}
                                }
								else{
									##Output-Message "Repeat server: $hostname"
								}	
							}
							else{
								#Output-Message "$ipaddress -> Unable to access"
							}	
						}
						else{
							#Output-Message "$ipaddress -> No connection"
						}	
					} # foreach ip range
                    New-Item "$scriptpath\csv" -Type Directory -EA SilentlyContinue > $null
                    $obj | Export-Csv -Path "$scriptpath\csv\$($ip).csv" -NoTypeInformation

                    $upload = UploadTo-FTP -localpath "$scriptpath\csv\$($ip).csv"

                    if ($upload -eq $true){

                    }
                    else{
                        Output-Message "Upload failed" -err
                    }

                    Remove-Item "$scriptpath\csv" -recurse -force -ea SilentlyContinue

                    # send email
                    if($global:encounteredError -eq $true){
                        Email-Result -Subnet "$subnet" -Error 
                    }
                    else{
                        Email-Result -Subnet "$subnet"
                    }
                } # foreach subnet
            }
		}	
	}
	End{

	}
}


Main-Program *>&1 | Tee -FilePath $global:LOGPATH -append
Clean-OldLogs