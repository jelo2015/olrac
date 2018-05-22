
#--Script path when compiled as an EXE
$global:scriptPath = pwd | Select-Object -ExpandProperty Path
$global:LOGPATH = $scriptPath + '\Logs\' + 'TCServer_Report_' + (Date -Format "yyyyMMddhhmmss") + '.log'
$global:Key = (3,4,2,3,56,34,254,222,1,1,2,23,42,54,33,233,1,34,2,7,6,5,35,43)


$VerbosePreference = "Continue"
$ErrorActionPreference = "Continue"

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
                if ($line -like "BaseVersion*") {
                    $global:BaseVersion = $line.Split('=')[1]
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
              
        #return $true
    }
    catch [Exception] {
        return $_
    }
}

function IPrange{
	param 
	( 
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
					$lowerversion = @()
					$ip = $subnet.Split('/')[0]
					$cidr = $subnet.Split('/')[1]
					$iprange = iprange -ip "$ip" -cidr $cidr
					$ReportPath = $scriptpath + "\Reports\" + ('TC-Server_Report_' + "$ip" + "_" + (date -Format "yyyyMMddHHmmss") + ".html")
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
										$tcserver = Get-WmiObject win32_service -ea stop -computername "$ipaddress" | Where { $_.name -like "*tcserver*"} 
										$servers += "$hostname"
									}
									catch{
										Output-Message "$($_)" -warn
									}

									if ($tcserver){

										Output-Message "$hostname -> Found TC server"

										foreach ($tc in $tcserver){
											# parse tc server pathname

											$pathname = $tc | Select-Object -ExpandProperty PathName

											if ($pathname){

												#instance name
												$a,$b = $pathname -split 'INSTANCE_NAME='
												$instancename = $b.split(' ')[0]
												Output-Message "Instance Name: $instancename"

												$c,$d = $pathname -split 'CATALINA_HOME='
												$version = $d.split('"')[0]
												$version = $version.split('\')[-1]
												
												Output-Message "Version: $version"

												$props = [ordered]@{
		                                            'Server Name'=$hostname
		                                            'IP Address'= "$ipaddress"
		                                            'Instance Name' = "$instancename"
		                                            'Version'= "$version"
		                                        }
		                                        $obj += @(New-Object pscustomobject -Property $props)

		                                        $versioning = $global:BaseVersion,$version | Sort-Object | Select-Object -first 1

		                                        if($versioning -ne $global:BaseVersion){
		                                        	Output-Message "Lower version detected: $version"
		                                        	$lowerversion += $version
		                                        }
											}
											else {
												Output-Message "$hostname -> unable to find PathName" -err    
											}
										} # foreach tcserver
									}
									else{
										#Output-Message "$hostname -> No TCServer found on server"
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

					# deploy object to html
					$html = $obj | Sort-Object -Property 'Server Name' | ConvertTo-Html -Head "$style" -Body "<strong><h5>$subnet</h5></strong>"

					if($lowerversion){
                        foreach ($x in $lowerversion){
                            $html = $html -replace "<td>$x</td>","<td  Style=`"background-color:red`">$x</td>"
                        }
                    }
					
					Add-Content $ReportPath $html

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
			     		
			            Output-Message "Checking for lock file"

			            # Get list of files in the directory
			            $lockfile = $session.ListDirectory($remotePath).Files | Where-Object {$_.Name -eq 'lock.lck'}

			            while($lockfile -ne $null){
			            	Output-Message "Lock file detected. Waiting for other process to complete"
			            	Sleep 10
			            	$lockfile = $session.ListDirectory($remotePath).Files | Where-Object {$_.Name -eq 'lock.lck'}
			            }

			            $null = New-Item -Type Directory "$scriptpath\Temp" -force
						$null = New-Item -Type File "$scriptpath\Temp\Lock.lck" -force

						Output-Message "Uploading lock file"

						$transferResult = $session.PutFiles("$scriptpath\Temp\Lock.lck","$remotepath/", $False, $transferOptions)
			            $transferResult.Check()
	                    if ($transferResult.IsSuccess){Output-Message "Upload of lock file succeeded"}
	                    else{Output-Message "Upload of lock file failed" -err}

	                    Output-Message "Checking for any existing report"

			            $file = $session.ListDirectory($remotePath).Files | Where-Object {$_.Name -like "$(get-date -format MMddyyyy).html"}

			            if ($file){
			            	Output-Message "Downloading existing report"
			            	$name = $file.Name
			            	$transferResult =  $session.GetFiles("$remotepath/$name","$scriptpath\temp\", $False, $transferOptions)
	                        $transferResult.Check()
	                        
	                        if ($transferResult.IsSuccess){Output-Message "Download of $name succeeded"}
	                        else{Output-Message "Download of $name failed" -err}
	                        Output-Message "Adding html table to the report"
	                        Add-Content "$scriptpath\temp\$name" $html
						}
			            else{
			            	$name = "$(get-date -format MMddyyyy).html"
			            	Output-Message "No existing report detected"
			            	Output-Message "Creating title table"
			            	$title = ConvertTo-Html -Head "$style" -Title "Tomcat Discovery" -Body "<h1>Tomcat Discovery</h1>"
	        				Add-Content "$scriptpath\Temp\$(get-date -format MMddyyyy).html" $title
	        				Output-Message "Adding html table"
							Add-Content "$scriptpath\Temp\$(get-date -format MMddyyyy).html" $html
						}

						Output-Message "Uploading report to ftp"
						$transferResult = $session.PutFiles("$scriptpath\Temp\$name","$remotepath/", $False, $transferOptions)
			            $transferResult.Check()
	                    if ($transferResult.IsSuccess){Output-Message "Upload of $name file succeeded"}
	                    else{Output-Message "Upload of $name file failed" -err}

	                    $lockfile = $session.ListDirectory($remotePath).Files | Where-Object {$_.Name -eq 'lock.lck'}

	                    $removalResult = $session.RemoveFiles("$remotepath/$($lockfile.Name)")
	 
		                if ($removalResult.IsSuccess){
		                    Output-Message "Removal of lock file succeeded"
		                }
		                else{
		                    Output-Message "Removal of lock file failed" -err
		                }

		                Output-Message "Closing ftp sessions"
		                $session.Dispose()

		                Output-Message "Removing temp directory"
		                remove-item "$scriptPath\Temp" -Force -EA SilentlyContinue -Recurse
		            }    
				} # foreach subnet
			}
		}	
	}
	End{

	}
}


Main-Program *>&1 | Tee -FilePath $global:LOGPATH -append