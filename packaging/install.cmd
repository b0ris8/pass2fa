@echo off
rem Установка pass2fa: программа, ярлык в «Пуске», хост для браузеров, файлы расширения.
chcp 65001 >nul
"%~dp0pass2fa.exe" install
echo.
pause
