@echo off
echo ^> Staging %1 ...
shift

:loop
set src=%~1
set dest=%~2
if "%src%"=="" goto done
if "%dest%"=="" goto error
echo f | xcopy /F/Y "%src%" "%dest%" | find " -> "
shift
shift
goto loop

:error
echo stage_helper: source "%1" has no destination?!
exit /b 1

:done
