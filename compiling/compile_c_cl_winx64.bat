@echo off
setlocal enabledelayedexpansion

REM === Compiler and default options ===
set COMPILER=cl
set OPTIONS=/O2 /GL /Gy /W3 /GS /Zc:wchar_t /Zc:inline /fp:precise /D NDEBUG /D _CONSOLE /D _UNICODE /D UNICODE /Zc:forScope /Gd /Oi /MD /EHsc /nologo /permissive- /FC /diagnostics:column

REM === Linker options for optimization and small size ===
set LINK_OPTS=/SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF /INCREMENTAL:NO /LTCG /MANIFEST:NO

REM === Check input arguments ===
if "%~1"=="" (
    echo Usage: %~nx0 filename.c [optional libraries...]
    echo Example: %~nx0 aes.c bcrypt.lib advapi32.lib
    exit /b 1
)

REM === Extract source file ===
set SRCFILE=%~1

REM === Remove first argument from command line and collect libs ===
shift
set LIBS=
:loop
if "%~1"=="" goto afterlibs
set LIBS=!LIBS! %1
shift
goto loop
:afterlibs

REM === Compile command ===
echo Compiling %SRCFILE% with cl.exe...
%COMPILER% %SRCFILE% %OPTIONS% %LIBS% /link %LINK_OPTS%

REM === Check if compilation succeeded ===
if errorlevel 1 (
    echo Compilation failed.
    exit /b 1
)

REM === Extract output exe name ===
for %%F in ("%SRCFILE%") do set BASENAME=%%~nF

REM === Strip executable with editbin if available ===
where editbin >nul 2>&1
if %errorlevel%==0 (
    echo Stripping executable with editbin /RELEASE...
    editbin /RELEASE "%BASENAME%.exe"
) else (
    echo editbin not found, skipping strip.
)

REM === Print final size ===
for %%F in ("%BASENAME%.exe") do echo Final EXE size: %%~zF bytes

endlocal

