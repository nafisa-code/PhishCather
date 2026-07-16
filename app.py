from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph
from flask import Flask, render_template, request,Response, send_file ,redirect, url_for,session
import sqlite3
import csv
from flask import Response
import os
import re
from email import policy
from email.parser import BytesParser
from functools import wraps

app = Flask(__name__)
app.secret_key = "phishcatcher_secret_key"
USERNAME = "admin"
PASSWORD_HASH = "scrypt:32768:8:1$Fcl6Qg8Div9CKh7A$e3715f72cc51397f21a8752df0d2d70e2ed68c6efa0311328e83cd5e5e3a94b496e7d7e27f77ad0fe26e8549f0b16bda1d0914143a892755f5a903c5c41d888b"
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def home():

    conn = sqlite3.connect("database/phishcatcher.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_emails = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level='HIGH'")
    high = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level='MEDIUM'")
    medium = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level='LOW'")
    low = cursor.fetchone()[0]
    cursor.execute("""
        SELECT threat_level
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """)
    last = cursor.fetchone()
    if last:
        latest_threat = last["threat_level"]
    else:
        latest_threat = "NONE"
    conn.close()

    return render_template(
        "index.html",
        total_emails=total_emails,
        high=high,
        medium=medium,
        low=low,
        latest_threat=latest_threat
    )
@app.route("/upload")
@login_required
def upload():
    return render_template("upload.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "email" not in request.files:
        return "No file uploaded!"
    file = request.files["email"]
    if file.filename == "":
        return "Please select an email file."
    if not file.filename.lower().endswith(".eml"):
        return "Only .eml files are allowed."
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    sender = msg.get("From", "Not Available")
    sender_match = re.search(r'@([A-Za-z0-9.-]+)', sender)
    if sender_match:
        sender_domain = sender_match.group(1).lower()
    else:
        sender_domain = "Unknown"
    suspicious_domains = [
        "tempmail.com",
        "mailinator.com",
        "10minutemail.com",
        "guerrillamail.com",
        "fakeinbox.com"
    ]
    receiver = msg.get("To", "Not Available")
    subject = msg.get("Subject", "Not Available")
    date = msg.get("Date", "Not Available")
    if sender_domain in suspicious_domains:
        sender_status = "Suspicious ❌"
    else:
        sender_status = "Safe ✅"
    spf_header = msg.get("Received-SPF", "")
    dkim_header = msg.get("DKIM-Signature", "")
    dmarc_header = msg.get("Authentication-Results", "")
    if "pass" in spf_header.lower():
        spf = "PASS ✅"
    elif spf_header:
        spf = "FAIL ❌"
    else:
        spf = "NOT FOUND"

    if dkim_header:
        dkim = "PRESENT ✅"
    else:
        dkim = "NOT FOUND"

    if "dmarc=pass" in dmarc_header.lower():
        dmarc = "PASS ✅"
    elif dmarc_header:
        dmarc = "FAIL ❌"
    else:
        dmarc = "NOT FOUND"
    body = ""
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
    received_headers = msg.get_all("Received", [])
    ip_addresses = []
    for header in received_headers:
        ips =re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)
        ip_addresses.extend(ips)
        #remove dup
    ip_addresses = list(set(ip_addresses))
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8",
                    errors="replace"
                )
                break
    else:
        body = msg.get_content()
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
    threat_score = 0
    url_results = []
    for url in urls:
        risk = "Safe"
        if len(url) > 75:
            risk = "Suspicious"
        elif url.count("-") >= 3:
            risk = "Suspicious"
        elif re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
            risk = "Suspicious"
        elif any(short in url for short in [
            "bit.ly",
            "tinyurl",
            "t.co",
            "goo.gl"
        ]):
            risk = "Suspicious"
        url_results.append({
            "url": url,
            "risk": risk
        })
        if risk == "Suspicious":
            threat_score += 15
    keywords = [
        "urgent",
        "verify",
        "password",
        "login",
        "account",
        "bank",
        "click here",
        "update",
        "free",
        "prize",
        "limited time"
    ]

    found_keywords = []
    subject_lower = subject.lower()
    body_lower = body.lower()
    for keyword in keywords:
        if keyword in subject_lower or keyword in body_lower:
            found_keywords.append(keyword)
            threat_score += 20
    threat_score += len(urls) * 10

    if len(urls) > 3:
        threat_score += 20
    if threat_score >= 60:
        threat_level = "HIGH"
    elif threat_score >= 30:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"
    conn = sqlite3.connect("database/phishcatcher.db")
    cursor = conn.cursor()
    cursor.execute("""INSERT INTO scans (sender, receiver, subject, date, threat_level, threat_score) VALUES (?, ?, ?, ?, ?, ?) """,
    (
        sender,
        receiver,
        subject,
        date,
        threat_level,
        threat_score
    ))

    conn.commit()
    conn.close()
    return render_template(
        "result.html",
        filename=file.filename,
        sender=sender,
        receiver=receiver,
        subject=subject,
        date=date,
        urls=urls,
        url_results=url_results,
        threat_score=threat_score,
        threat_level=threat_level,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        found_keywords=found_keywords,
        attachments=attachments,
        ip_addresses=ip_addresses,
        sender_status=sender_status,
        sender_domain=sender_domain
    )
@app.route("/history")
@login_required
def history():

    conn = sqlite3.connect("database/phishcatcher.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans ORDER BY id DESC")
    scans = cursor.fetchall()

    conn.close()

    return render_template("history.html", scans=scans)
@app.route("/export/csv")
@login_required
def export_csv():
    conn = sqlite3.connect("database/phishcatcher.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, sender, receiver, subject, date,
               threat_level, threat_score
        FROM scans
        ORDER BY id DESC
    """)
    scans = cursor.fetchall()
    conn.close()
    def generate():
        data = csv.writer(Echo())
        yield data.writerow([
            "ID",
            "Sender",
            "Receiver",
            "Subject",
            "Date",
            "Threat Level",
            "Threat Score"
        ])
        for row in scans:
            yield data.writerow(row)
    return Response(
        generate(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=scan_history.csv"
        }
    )
class Echo:
    def write(self, value):
        return value

@app.route("/export/pdf")
@login_required
def export_pdf():
    conn = sqlite3.connect("database/phishcatcher.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, sender, receiver, subject,
               date, threat_level, threat_score
        FROM scans
        ORDER BY id DESC
    """)
    scans = cursor.fetchall()
    conn.close()
    pdf_file = "scan_history.pdf"
    doc = SimpleDocTemplate(pdf_file)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("PhishCatcher Scan History Report", styles["Heading1"]))
    data = [[
        "ID",
        "Sender",
        "Receiver",
        "Subject",
        "Date",
        "Threat",
        "Score"
    ]]

    for row in scans:
        data.append(row)
    table = Table(data)
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.darkblue),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),1,colors.black),
        ("BACKGROUND",(0,1),(-1,-1),colors.beige),
        ("ALIGN",(0,0),(-1,-1),"CENTER"),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("BOTTOMPADDING",(0,0),(-1,0),10)
    ]))

    elements.append(table)
    doc.build(elements)
    return send_file(
        pdf_file,
        as_attachment=True
    )
@app.route("/about")
def about():
    return render_template("about.html")
@app.route("/dashboard")
@login_required
def dashboard():
    conn = sqlite3.connect("database/phishcatcher.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_emails = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level='LOW'")
    low = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level='MEDIUM'")
    medium = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level='HIGH'")
    high = cursor.fetchone()[0]

    cursor.execute("""
        SELECT sender, subject, threat_level, threat_score
        FROM scans
        ORDER BY id DESC
        LIMIT 5
    """)
    scans = cursor.fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        total_emails=total_emails,
        low=low,
        medium=medium,
        high=high,
        scans=scans
    )
@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))
if __name__ == "__main__":
    app.run(debug=True)