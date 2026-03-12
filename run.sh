#!/bin/bash
echo "============================================"
echo "  Visual Network Tracker — Starting Up"
echo "============================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found. Please install Python 3.10+"
    exit 1
fi

# Install dependencies silently
echo "Installing dependencies..."
pip install flask flask-cors python-dateutil -q

# Initialize database
cd backend
python3 -c "from database import init_db; init_db(); print('✓ Database ready')"

echo "✓ Starting server on http://localhost:5000"
echo "✓ Open http://localhost:5000 in your browser"
echo ""
python3 app.py
