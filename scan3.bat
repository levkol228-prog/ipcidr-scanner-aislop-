@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File scan.ps1
