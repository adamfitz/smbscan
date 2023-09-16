# Inspiration taken from here:
# https://www.youtube.com/watch?v=MHsI8hJmggI&t=2473s&ab_channel=JoshMadakor

$user_list = Get-Content .\users.txt

function Get-RandomPassword {
    $charsArray = "abcdefghijkmnopqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ0123456789!\#$%&''()*+,-./:;<=>?@[\]^_`{|}~".ToCharArray()
$randomObject = New-Object System.Random
$randomString = ""
for ($i = 0; $i -lt 10; $i++) {
    $randomIndex = $randomObject.Next(0, $charsArray.Length)
    $randomCharacter = $charsArray[$randomIndex]
    $randomString += $randomCharacter
}
return $randomString
}


foreach ($n in $user_list) {
    # generate a random character string for the password 
    $user_password = Get-RandomPassword 
    $secure_password =  ConvertTo-SecureString $user_password -AsPlainText -Force
    $first = $n.Split(" ")[0].ToLower()
    $last = $n.Split(" ")[1].ToLower()
    $username = "$($first.Substring(0,1))$($last)".ToLower()
    Write-Host "Creating User: $($username), Password: $($user_password )" -BackgroundColor Black -ForegroundColor Cyan
    
    New-AdUser -AccountPassword $secure_password `
               -GivenName $first `
               -Surname $last `
               -DisplayName $username `
               -Name $username `
               -EmployeeID $username `
               -PasswordNeverExpires $True `
               -Path "ou=nn_users,$(([ADSI]`"").distinguishedName)" `
               -Enabled $True
}