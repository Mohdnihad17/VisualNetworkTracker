@echo off
echo ============================================
echo   Visual Network Tracker
echo ============================================
echo.
echo Installing dependencies...
pip install flask flask-cors python-dateutil -q
echo.
echo Starting backend server...
cd /d "C:\Users\mhdni\vnt claude\VisualNetworkTracker\backend"
start /b python app.py
echo.
echo Waiting for server to start...
timeout /t 3 /nobreak >nul
echo.
echo Opening browser...
start "" "http://localhost:5000"
echo.
echo ============================================
echo  Server is RUNNING at localhost:5000
echo.
echo  CLOSE THIS WINDOW TO STOP THE SERVER
echo ============================================
echo.
pause >nul
taskkill /f /im python.exe >nul 2>&1
echo.
echo Server stopped. Goodbye.
timeout /t 2 /nobreak >nul
exit
```

---