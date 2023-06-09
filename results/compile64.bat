@echo off
setlocal enabledelayedexpansion

set "folder=%~dp0"

for %%F in ("%folder%\*") do (
    set "extension=%%~xF"
    if /i "!extension!"==".cpp" (
        echo ### Processing %%~nxF a###
        REM Perform actions for .cpp files here
		x86_64-w64-mingw32-g++.exe  %%~nxF -o %%~nxF.exe
    ) else if /i "!extension!"==".cs" (
        echo ### Processing %%~nxF ###
        REM Perform actions for .cs files here
		C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /platform:x64 /out:%%~nxF.exe %%~nxF
    ) else (
        echo Unsupported file extension: %%~nxF
        REM Handle unsupported file extensions here
    )
)
pause
endlocal

