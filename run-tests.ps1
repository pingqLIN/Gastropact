$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
python -m unittest discover -s (Join-Path $root 'tests') -v
