# get directory name
$new_dir = $args[0]
Write-Host "Creating new directory for share: $new_dir"
# create new directory
New-Item -Path "." -Name $new_dir -ItemType "directory"
$share_params = @{
    Name = $new_dir 
    Path = "Q:\$new_dir"
    #ChangeAccess = 'CONTOSO\Finance Users','CONTOSO\HR Users'
    #FullAccess = 'Administrators'
}

# create smb share
New-SmbShare @share_params

