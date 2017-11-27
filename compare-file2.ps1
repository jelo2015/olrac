$ServerList = Import-Csv -Path C:\Scripts\Reports\Discovery_rem.csv
$ServerData = Import-Csv -Path C:\Scripts\Reports\SL_rem.csv
$serverOutput = @()
$serverOutputver2 = @()
$serverOutputver3 = @()


    foreach ($name in $ServerList) {
    

        $serverMatch = $serverData | where {$_.servername -eq $name.servername}
            If (!$serverMatch) {       
                $vm = $name.ServerName         
                $comment = "$vm is not in SL_all.csv."                        
                      
                       
                $serverOutput += New-Object PsObject -Property ([ordered] @{ServerName =$name.servername;IP =$name.IP;Comment="$comment"})
            }
    }
    
  $serverOutput | Out-Null

    foreach ($server in $ServerData) {
    
        $ServerMatchver2 = $ServerList| where {$_.servername -eq $server.servername}
            if (!$serverMatchver2) {              

                $serverOutputver2 += New-Object PsObject -Property ([ordered] @{ServerName =$server.servername;IP =$server.IP})
             } 
    }
            
  $serverOutputver2 | Out-Null

    foreach ($machine in $serverOutputver2) {
        $comparison = $serverOutput | where {$_.servername -eq $machine.servername}
            if (!$comparison) {
                $vm = $machine.ServerName
                $comment = "$vm is not in Discovery.csv." 
                
                $serverOutputver3  += New-Object PsObject -Property ([ordered] @{ServerName =$machine.servername;IP =$machine.IP;comment=$comment})
            
            }
    }   
    
    
$output = $serverOutput + $serverOutputver3
#$output
#$serverOutput | ft    
$output | Export-Csv C:\Scripts\Output\Discovery\Result\result.csv -NoTypeInformation