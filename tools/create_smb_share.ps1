$new_dir = $args[0]
Write-Host "Creating new directory for share: $new_dir"
New-Item -Path "." -Name $new_dir -ItemType "directory"
