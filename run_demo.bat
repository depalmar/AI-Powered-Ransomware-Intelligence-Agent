@echo off
echo 🛡️  Starting Mock Ransomware.live API Server...
echo --------------------------------------------------
echo 🔗  Local API: http://localhost:3000
echo 📝  Use the "DEMO" n8n workflow for safe testing.
echo.
python mock_api/server.py
pause