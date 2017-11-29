#####################################################################################
# This script compares xml files in two folders and get files with unique file name #
# and also compares contents for those with similar file names.                      #
#####################################################################################


#Get xml files in folders
$folder2 = Get-ChildItem D:\Folder\Carlo\Tests\Files\Folder2\ -filter *.xml #newer folder 
$folder1 = Get-ChildItem D:\Folder\Carlo\Tests\Files\Folder1\ -filter *.xml #older folder - required

#Define folders
$dir1 = "D:\Folder\Carlo\Tests\Files\Folder1" # - required
$dir2 = "D:\Folder\Carlo\Tests\Files\Folder2" # - required
$dir3 = "D:\Folder\Carlo\Tests\Files\Folder3" # - required

#Define empty arrays
$txtchanged=@()
$file4copy=@()


#Define files which are not in folder1
$file_compare = ((Compare-Object $folder1 $folder2 |where {$_.sideindicator -eq "=>"}).Inputobject).Name


#Define files which contents are changed
$filelist = Compare-Object $folder1 $folder2 -ExcludeDifferent -IncludeEqual
foreach ($xml in $filelist) {
    $F2 = $dir2 + "\" + $xml.inputObject
    $F1 = $dir1 + "\" + $xml.inputObject
        $Compare = Compare-Object $(Get-Content $F2) $(Get-Content $F1)
        $side = $compare | where {$_.sideindicator -eq "<=" -or $_.sideindicator -eq "=>"}
            if ($side) {
                $diff = $F2.Split("\")[-1]                
                $txtchanged += $diff
                
            }
}

#List down results

Write-Host "Files which are not in folder1:" -ForegroundColor DarkYellow
$file_compare
""
""
Write-Host "XML with different contents but same file name:" -ForegroundColor DarkYellow
$txtchanged

$txtchanged += $file_compare

foreach ($file in $txtchanged) {
    $xml4copy=  $dir2 + "\" + $file
    $file4copy += $xml4copy
}
""
""

Write-Host "Files to be copied to Folder3" -ForegroundColor DarkYellow
$file4copy

""
""

#Copy files to Folder3
foreach ($copy in $file4copy) {
    
    Copy-Item $copy $dir3 -Force
    
    
}
