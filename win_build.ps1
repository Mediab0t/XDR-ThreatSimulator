python -V
pip install -r requirements.txt
pyinstaller --onefile main.py

$date = Get-Date -Format "yyyy-MM-dd-HH-mm-ss-"
$rstring = (-join (((48..57)+(65..90)+(97..122)) * 80 | Get-Random -Count 16 |%{[char]$_}))
$jstring = $date + $rstring + '.exe'

mv .\dist\main.exe $jstring
ls

Write-Host ''
Write-Host 'Output file:' $jstring