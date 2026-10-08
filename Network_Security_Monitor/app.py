from flask import Flask,render_template,request,jsonify
import sqlite3,re
from datetime import datetime
app=Flask(__name__); DB="events.db"
def con():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init():
 c=con(); c.execute("""CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,timestamp TEXT,ip TEXT,message TEXT,severity TEXT)"""); c.commit(); c.close()
def classify(m):
 if re.search(r"malware|trojan|ransomware|port scan",m,re.I): return "High"
 if re.search(r"failed login|blocked|denied",m,re.I): return "Medium"
 return "Low"
@app.get("/")
def home(): return render_template("index.html")
@app.get("/api/events")
def events():
 c=con(); r=c.execute("SELECT * FROM events ORDER BY id DESC").fetchall(); c.close(); return jsonify([dict(x) for x in r])
@app.post("/api/analyze")
def analyze():
 d=request.get_json(); m=d.get("message","").strip(); ip=d.get("ip","127.0.0.1")
 if not m:return jsonify(error="Enter an event message"),400
 s=classify(m); c=con(); c.execute("INSERT INTO events(timestamp,ip,message,severity) VALUES(?,?,?,?)",(datetime.now().strftime("%Y-%m-%d %H:%M:%S"),ip,m,s)); c.commit(); c.close()
 return jsonify(severity=s)
@app.post("/api/clear")
def clear():
 c=con(); c.execute("DELETE FROM events"); c.commit(); c.close(); return jsonify(ok=True)
init()
if __name__=="__main__": app.run(debug=True)
