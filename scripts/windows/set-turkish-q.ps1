$ErrorActionPreference = 'Stop'
$inputTip = '041f:0000041f'
$languageList = Get-WinUserLanguageList
$turkish = $languageList |
    Where-Object { $_.LanguageTag -eq 'tr-TR' } |
    Select-Object -First 1

if ($null -eq $turkish) {
    $turkish = (New-WinUserLanguageList -Language 'tr-TR')[0]
    [void] $languageList.Add($turkish)
}

$turkish.InputMethodTips.Clear()
[void] $turkish.InputMethodTips.Add($inputTip)

Set-WinUserLanguageList -LanguageList $languageList -Force
Set-WinDefaultInputMethodOverride -InputTip $inputTip

Write-Host ''
Write-Host 'Turkish Q keyboard is now the default.'
Write-Host 'Sign out or restart Windows to apply it everywhere.'
Read-Host 'Press Enter to close'
