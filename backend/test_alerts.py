import app, json, urllib.request

print("--- DIRECT FUNCTION CALL ---")
try:
    with app.app.app_context():
        res = app.get_alerts().get_json()
        print(json.dumps(res[0] if res else [], indent=2))
except Exception as e:
    print("Error:", e)

print("\n--- LIVE SERVER CALL ---")
try:
    live = json.loads(urllib.request.urlopen('http://localhost:5000/api/alerts').read().decode('utf-8'))
    print(json.dumps(live[0] if live else [], indent=2))
except Exception as e:
    print("Error:", e)
