Write-Host @"
______           _     _               ______                       _          
| ___ \         (_)   | |              |  ___|                     (_)         
| |_/ /___  __ _ _ ___| |_ _ __ _   _  | |_ ___  _ __ ___ _ __  ___ _  ___ ___ 
|    // _ \/ _` | / __| __| '__| | | | |  _/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
| |\ \  __/ (_| | \__ \ |_| |  | |_| | | || (_) | | |  __/ | | \__ \ | (__\__ \
\_| \_\___|\__, |_|___/\__|_|   \__, | \_| \___/|_|  \___|_| |_|___/_|\___|___/
            __/ |                __/ |                                         
           |___/                |___/  

[*] This Tool Created By Zyad Elzyat

"@ -ForegroundColor Cyan

function Show-RegistryItems {
    param (
        [string]$registryPath
    )

    $registryKey = Get-Item -LiteralPath $registryPath -ErrorAction SilentlyContinue

    if ($registryKey -eq $null) {
        Write-Host "Registry path not found: $registryPath" -ForegroundColor Red
        return
    }

    Write-Host "Listing items in registry path: $registryPath" -ForegroundColor Green
    $registryKey.GetValueNames() | ForEach-Object {
        $_
    }
}

function Delete-RegistryItem {
    param (
        [string]$registryPath,
        [string]$item
    )

    $confirmation = Read-Host "Are you sure you want to delete '$item' from '$registryPath'? (Y/N)"

    if ($confirmation -eq 'Y' -or $confirmation -eq 'y') {
        try {
            Remove-ItemProperty -Path $registryPath -Name $item -ErrorAction Stop
            Write-Host "Item '$item' deleted successfully." -ForegroundColor Green
        } catch {
            Write-Host "Failed to delete item. $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Deletion cancelled." -ForegroundColor Yellow
    }
}

function Export-RegistrySnapshot {
    [CmdletBinding()]
    Param(
        [Parameter(Position=1, Mandatory=$True)]
        [string]$outputFile
    )
    $data = @{}

    $locations = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Policies\Microsoft\Windows\System\Scripts",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    )

    "Creating snapshot..."

    foreach ($loc in $locations) {
        $keys = Get-Item -ErrorAction SilentlyContinue $loc | select -exp Property
        $data[$loc] = @{}
        foreach ($key in $keys) {
            $value = Get-ItemPropertyValue $loc -Name $key
            $data[$loc][$key] = $value
        }
    }

    "Snapshot created."
    $data | ConvertTo-Json > "$outputFile.json"

    "Saved Object: $outputFile.json"
}

function Choose-Option {
    Write-Host "Choose an option:"
    Write-Host "[1.] Export Registry Snapshot"
    Write-Host "[2.] Delete Registry Items"

    $choice = Read-Host "Enter your choice (1 or 2): "

    switch ($choice) {
        1 { Export-RegistrySnapshot }
        2 { Show-RegistryItemsAndDelete }
        default { Write-Host "Invalid choice. Please enter 1 or 2." }
    }
}

function Show-RegistryItemsAndDelete {
    # Registry paths
    $registryPaths = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Environment"
    )

    # Additional Registry paths
    $additionalRegistryPaths = @(
        "HKCU:\Control Panel\International",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    # Add the additional paths to the existing paths
    $registryPaths += $additionalRegistryPaths

    # Select a registry path
    $selectedPath = $registryPaths | Out-GridView -Title "Select Registry Path" -PassThru

    if ($selectedPath) {
        # List items and provide option to delete in a new window
        $itemList = Show-RegistryItems -registryPath $selectedPath

        if ($itemList.Count -eq 0) {
            Write-Host "No items found in $selectedPath" -ForegroundColor Yellow
        } else {
            $itemsToDelete = $itemList | Out-GridView -Title "Select Items to Delete" -OutputMode Multiple

            if ($itemsToDelete.Count -eq 0) {
                Write-Host "No items selected for deletion." -ForegroundColor Yellow
            } else {
                foreach ($item in $itemsToDelete) {
                    Delete-RegistryItem -registryPath $selectedPath -item $item
                }
            }
        }
    }
}

Choose-Option
