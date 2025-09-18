@echo off
echo ===============================
echo 🚀 Starting Symptom Checker App
echo ===============================

:: Step 1: Start Node.js server
cd server
echo Starting Node.js server...
start cmd /k node server.js

:: Step 2: Open frontend
cd ../Website
echo Opening website in browser...
start index.html

echo ===============================
echo ✅ App is running! 
echo ===============================
pause
