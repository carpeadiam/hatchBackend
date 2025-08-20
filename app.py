import os
import psycopg2
import jwt
import uuid
import logging
from flask import Flask, request, jsonify
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from pymongo import MongoClient
from email.message import EmailMessage
import ssl
import smtplib
from datetime import datetime, timezone
from plagiarism_checker import PlagiarismChecker, Config as PlagiarismConfig

# --- Logging setup ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)
app = Flask(__name__)

# --- Config ---
DB_CONNECTION = os.getenv("AZURE_POSTGRESQL_CONNECTIONSTRING")
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-azure")

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI")
mongo_client = MongoClient(MONGO_URI)
mongo_db = mongo_client["hackdb"]             # database name
hackathons = mongo_db["hackathons"]           # collection name

# Email credentials (use env vars ideally)
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "adi.profile1@gmail.com")  # Replace with your Gmail address
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "gwaryitmlyzygepr")   # Use app password (not your login password)

# --- DB helpers ---
def get_connection():
    if not DB_CONNECTION:
        raise RuntimeError("AZURE_POSTGRESQL_CONNECTIONSTRING is not set")
    return psycopg2.connect(DB_CONNECTION, cursor_factory=RealDictCursor)

def create_users_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS Users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

create_users_table()

# --- Auth helpers ---
def create_token(user_id, email):
    payload = {"user_id": user_id, "email": email}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth_header.split(" ", 1)[1].strip()
        try:
            user = decode_token(token)
            request.user = user
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper

# --- Email functionality ---
def send_added_to_team_email(email_to, creator_name="Your team leader"):
    subject = "You're part of a team on Hatch!"
    body = f"""
    <html>
    <body style="background-color: #ffffff; color: #2ecc71; font-family: Arial, sans-serif; text-align: center;">
        <h1>🎉 Welcome to Hatch!</h1>
        <p>You've been added to a team by <strong>{creator_name}</strong> for a Hackathon.</p>
        <p style="font-size: 18px;">Get ready to innovate!</p>
        <br><br>
        <footer style="color: gray; font-size: 12px;">This is an automated message from Hatch.</footer>
    </body>
    </html>
    """

    em = EmailMessage()
    em["From"] = EMAIL_ADDRESS
    em["To"] = email_to
    em["Subject"] = subject
    em.set_content(body, subtype="html")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.sendmail(EMAIL_ADDRESS, email_to, em.as_string())

# --- Routes ---
@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if "@" not in email:
        return jsonify({"error": "Invalid email"}), 400

    hashed = generate_password_hash(password)

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM Users WHERE email = %s", (email,))
        if cur.fetchone():
            cur.close(); conn.close()
            return jsonify({"error": "User already exists"}), 409

        cur.execute("INSERT INTO Users (email, password) VALUES (%s, %s) RETURNING id;", (email, hashed))
        user_id = cur.fetchone()["id"]
        conn.commit()
        cur.close(); conn.close()

        token = create_token(user_id, email)
        return jsonify({"message": "Signup successful", "token": token, "user": {"id": user_id, "email": email}}), 201
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, password FROM Users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close(); conn.close()

        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = create_token(user["id"], user["email"])
        return jsonify({"message": "Login successful", "token": token, "user": {"id": user["id"], "email": user["email"]}}), 200
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500

@app.route("/hack-create", methods=["POST"])
@token_required
def hack_create():
    """Create a hackathon entry in MongoDB"""
    data = request.get_json(silent=True) or {}
    user_email = request.user["email"]

    logger.debug("Received hackathon create request from user=%s, data=%s", user_email, data)

    # generate unique code
    hack_code = "HACK-" + uuid.uuid4().hex[:8].upper()

    # extend data with admins list + code
    hackathon_doc = data.copy()
    hackathon_doc["hackCode"] = hack_code
    hackathon_doc["admins"] = [user_email]

    try:
        result = hackathons.insert_one(hackathon_doc)
        logger.info("Hackathon created successfully: hackCode=%s id=%s", hack_code, result.inserted_id)
        return jsonify({
            "message": "Hackathon created",
            "hackCode": hack_code,
            "id": str(result.inserted_id)
        }), 201
    except Exception as e:
        logger.exception("Error while inserting hackathon into MongoDB")
        return jsonify({
            "error": "MongoDB insert failed",
            "details": str(e),
            "event": hackathon_doc
        }), 500

@app.route("/allHacks", methods=["GET"])
def get_all_hacks():
    hacks = list(hackathons.find({}, {"_id": 0}))  
    # ^ exclude _id because it's not JSON serializable
    return jsonify(hacks)

@app.route("/fetchhack", methods=["GET"])
def fetch_hack():
    hack_code = request.args.get("hackCode")  # expects ?hackCode=HACK-12345
    if not hack_code:
        return jsonify({"error": "hackCode is required"}), 400
    
    hack = hackathons.find_one({"hackCode": hack_code}, {"_id": 0})
    if not hack:
        return jsonify({"error": "Hackathon not found"}), 404
    
    return jsonify(hack)


@app.route("/registerteam", methods=["POST"])
@token_required
def register_team():
    data = request.get_json(silent=True) or {}
    hack_code = data.get("hackCode")
    if not hack_code:
        return jsonify({"error": "hackathonCode is required"}), 400

    # Fetch hackathon
    hack = hackathons.find_one({"hackCode": hack_code})
    if not hack:
        return jsonify({"error": "Hackathon not found"}), 404

    # Users collection (separate DB)
    users_db = mongo_client["usersdb"]
    users_collection = users_db["users"]

    team_leader = data.get("teamLeader", {})
    team_members = data.get("teamMembers", [])
    all_members = [team_leader] + team_members
    final_members = []
    
    # validate leader first
    leader_email = (team_leader.get("email") or "").lower().strip()
    if not leader_email:
        return jsonify({"error": "Team leader email required"}), 400

    leader_doc = users_collection.find_one({"email": leader_email})
    if leader_doc and any(h["hackCode"] == hack_code for h in leader_doc.get("hackathonsRegistered", [])):
        return jsonify({"error": f"Leader {leader_email} already registered in this hackathon"}), 400

    # Generate unique teamId (before looping so we can use it for each user)
    team_id = str(uuid.uuid4())

    # check and update each member
    for member in all_members:
        email = (member.get("email") or "").lower().strip()
        if not email:
            continue
        user_doc = users_collection.find_one({"email": email})
        if user_doc:
            if any(h["hackCode"] == hack_code for h in user_doc.get("hackathonsRegistered", [])):
                # skip member already registered
                if email == leader_email:
                    return jsonify({"error": f"Leader {email} already registered"}), 400
                continue
            else:
                # add hackathon with teamId
                users_collection.update_one(
                    {"email": email},
                    {"$addToSet": {
                        "hackathonsRegistered": {
                            "hackCode": hack_code,
                            "teamId": team_id
                        }
                    }}
                )
        else:
            # create new user
            users_collection.insert_one({
                "email": email,
                "hackathonsRegistered": [{
                    "hackCode": hack_code,
                    "teamId": team_id
                }],
                "hackathonsCreated": []
            })
        final_members.append(member)

        # Send email notification
        try:
            creator_name = team_leader.get("name", "Your team leader")
            send_added_to_team_email(email_to=email, creator_name=creator_name)
        except Exception as e:
            logger.error(f"❌ Email failed to {email}: {str(e)}")

    if not final_members or final_members[0].get("email") != leader_email:
        return jsonify({"error": "Team leader missing or invalid after validation"}), 400

    # Construct team registration object
    team_obj = {
        "teamId": team_id,
        "teamName": data.get("teamName"),
        "teamLeader": final_members[0],
        "teamMembers": final_members[1:],  # rest after leader
        "paymentDetails": data.get("paymentDetails", {}),
    }

    # Insert into hackathon registrations
    hackathons.update_one(
        {"hackCode": hack_code},
        {"$push": {"registrations": team_obj}}
    )

    return jsonify({
        "message": "Team registered successfully",
        "team": team_obj
    }), 201


@app.route("/managehack", methods=["POST"])
@token_required
def manage_hack():
    """
    Manage a hackathon (only admins allowed).
    Payload:
    {
        "hackCode": "HACK-XXXX",
        "action": "update" | "view" | "add_admin" | "remove_admin",
        "updateFields": {...},    # for action=update
        "adminEmail": "..."       # for add/remove admin
    }
    """
    data = request.get_json(silent=True) or {}
    hack_code = data.get("hackCode")
    action = data.get("action")
    user_email = request.user["email"]

    if not hack_code or not action:
        return jsonify({"error": "hackCode and action are required"}), 400

    hack = hackathons.find_one({"hackCode": hack_code})
    if not hack:
        return jsonify({"error": "Hackathon not found"}), 404

    # --- check if requester is admin ---
    if user_email not in hack.get("admins", []):
        return jsonify({"error": "Not authorized. Only admins can manage this hackathon."}), 403

    # --- handle actions ---
    if action == "view":
        # show hackathon details including registrations
        hack["_id"] = str(hack["_id"])  # make JSON safe
        return jsonify(hack), 200

    elif action == "update":
        update_fields = data.get("updateFields", {})
        if not update_fields:
            return jsonify({"error": "updateFields is required for update action"}), 400
        hackathons.update_one(
            {"hackCode": hack_code},
            {"$set": update_fields}
        )
        return jsonify({"message": "Hackathon updated successfully"}), 200

    elif action == "add_admin":
        new_admin = (data.get("adminEmail") or "").lower().strip()
        if not new_admin:
            return jsonify({"error": "adminEmail is required"}), 400
        hackathons.update_one(
            {"hackCode": hack_code},
            {"$addToSet": {"admins": new_admin}}
        )
        return jsonify({"message": f"{new_admin} added as admin"}), 200

    elif action == "remove_admin":
        remove_admin = (data.get("adminEmail") or "").lower().strip()
        if not remove_admin:
            return jsonify({"error": "adminEmail is required"}), 400
        if remove_admin == user_email:
            return jsonify({"error": "You cannot remove yourself"}), 400
        hackathons.update_one(
            {"hackCode": hack_code},
            {"$pull": {"admins": remove_admin}}
        )
        return jsonify({"message": f"{remove_admin} removed from admins"}), 200

    else:
        return jsonify({"error": f"Unknown action: {action}"}), 400
@app.route("/getTeamDetails", methods=["POST"])
@token_required
def get_team_details():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    hack_code = data.get("hackCode")

    if not email or not hack_code:
        return jsonify({"error": "email and hackCode are required"}), 400

    # --- Step 1: Check usersDB for email ---
    users_db = mongo_client["usersdb"]
    users_collection = users_db["users"]

    user_doc = users_collection.find_one({"email": email})
    if not user_doc:
        return jsonify({
            "message": "User not found",
            "registrationStatus": "no",
            "team": None
        }), 200

    # --- Step 2: Verify hackCode in hackathonsRegistered ---
    reg_entry = next(
        (h for h in user_doc.get("hackathonsRegistered", []) if h["hackCode"] == hack_code),
        None
    )

    if not reg_entry:
        return jsonify({
            "message": f"User {email} is not registered in hackathon {hack_code}",
            "registrationStatus": "no",
            "team": None
        }), 200

    team_id = reg_entry["teamId"]

    # --- Step 3: Fetch hackathon from hackdb ---
    hack_db = mongo_client["hackdb"]
    hackathons_collection = hack_db["hackathons"]

    hackathon_doc = hackathons_collection.find_one({"hackCode": hack_code}, {"_id": 0})
    if not hackathon_doc:
        return jsonify({"error": "Hackathon not found"}), 404

    # --- Step 4: Find team details inside hackathon.registrations ---
    team_details = next(
        (t for t in hackathon_doc.get("registrations", []) if t["teamId"] == team_id),
        None
    )

    return jsonify({
        "message": "Team details fetched successfully",
        "registrationStatus": "yes",
        "hackathon": {
            "hackCode": hackathon_doc.get("hackCode"),
            "eventName": hackathon_doc.get("eventName"),
            "eventDescription": hackathon_doc.get("eventDescription"),
            "eventStartDate": hackathon_doc.get("eventStartDate"),
            "eventEndDate": hackathon_doc.get("eventEndDate"),
        },
        "team": team_details
    }), 200

@app.route("/leaveTeam", methods=["POST"])
@token_required
def leave_team():
    data = request.get_json(silent=True) or {}
    hack_code = data.get("hackCode")
    email = (data.get("email") or "").strip().lower()

    if not hack_code or not email:
        return jsonify({"error": "hackCode and email are required"}), 400

    # --- Users DB ---
    users_db = mongo_client["usersdb"]
    users_collection = users_db["users"]

    user_doc = users_collection.find_one({"email": email})
    if not user_doc:
        return jsonify({"error": f"User {email} not found"}), 404

    reg_entry = next(
        (h for h in user_doc.get("hackathonsRegistered", []) if h["hackCode"] == hack_code),
        None
    )
    if not reg_entry:
        return jsonify({"error": f"User {email} not registered in hackathon {hack_code}"}), 404

    team_id = reg_entry["teamId"]

    # --- Hackathon DB ---
    hack = hackathons.find_one({"hackCode": hack_code})
    if not hack:
        return jsonify({"error": "Hackathon not found"}), 404

    team = next((t for t in hack.get("registrations", []) if t["teamId"] == team_id), None)
    if not team:
        return jsonify({"error": "Team not found"}), 404

    # --- Remove user from team ---
    if team.get("teamLeader", {}).get("email") == email:
        # If leader leaves, promote first member if exists, else delete team
        if team.get("teamMembers"):
            new_leader = team["teamMembers"].pop(0)
            team["teamLeader"] = new_leader
        else:
            # delete team entirely
            hackathons.update_one(
                {"hackCode": hack_code},
                {"$pull": {"registrations": {"teamId": team_id}}}
            )
    else:
        # Remove from teamMembers
        team["teamMembers"] = [m for m in team.get("teamMembers", []) if m.get("email") != email]

        # If no members + no leader → delete team
        if not team.get("teamMembers") and not team.get("teamLeader"):
            hackathons.update_one(
                {"hackCode": hack_code},
                {"$pull": {"registrations": {"teamId": team_id}}}
            )
        else:
            # Otherwise, update team with new members
            hackathons.update_one(
                {"hackCode": hack_code, "registrations.teamId": team_id},
                {"$set": {"registrations.$": team}}
            )

    # --- Remove hackathon from user's record ---
    users_collection.update_one(
        {"email": email},
        {"$pull": {"hackathonsRegistered": {"hackCode": hack_code}}}
    )

    return jsonify({
        "message": f"{email} left team {team_id} in hackathon {hack_code} successfully"
    }), 200

@app.route("/submissions", methods=["POST"])
@token_required
def submissions():
    data = request.get_json(silent=True) or {}
    hack_code = data.get("hackCode")
    team_id = data.get("teamId")
    phase_index = data.get("phaseIndex")
    submission_content = data.get("submissions")

    if not hack_code or not team_id or phase_index is None or not submission_content:
        return jsonify({"error": "hackCode, teamId, phaseIndex and submissions are required"}), 400

    # Fetch hackathon
    hack = hackathons.find_one({"hackCode": hack_code})
    if not hack:
        return jsonify({"error": "Hackathon not found"}), 404

    # Find the team inside registrations
    team = next((t for t in hack.get("registrations", []) if t["teamId"] == team_id), None)
    if not team:
        return jsonify({"error": "Team not found"}), 404

    # Ensure submissions array exists
    if "submissions" not in team:
        team["submissions"] = []

    # Check if phaseIndex already exists
    existing = next((s for s in team["submissions"] if s["phaseId"] == phase_index), None)
    if existing:
        existing["submissions"] = submission_content
    else:
        team["submissions"].append({
            "phaseId": phase_index,
            "submissions": submission_content
        })

    # Update team in DB
    hackathons.update_one(
        {"hackCode": hack_code, "registrations.teamId": team_id},
        {"$set": {"registrations.$": team}}
    )

    return jsonify({
        "message": "Submission saved successfully",
        "teamId": team_id,
        "phaseIndex": phase_index,
        "submission": submission_content
    }), 200


@app.route("/fetchsubmissions", methods=["GET"])
@token_required
def fetch_submissions():
    hack_code = request.args.get("hackCode")
    team_id = request.args.get("teamId")

    if not hack_code or not team_id:
        return jsonify({"error": "hackCode and teamId are required"}), 400

    hack = hackathons.find_one({"hackCode": hack_code}, {"_id": 0})
    if not hack:
        return jsonify({"error": "Hackathon not found"}), 404

    team = next((t for t in hack.get("registrations", []) if t["teamId"] == team_id), None)
    if not team:
        return jsonify({"error": "Team not found"}), 404

    return jsonify({
        "teamId": team_id,
        "submissions": team.get("submissions", [])
    }), 200

@app.route("/announcements", methods=["POST"])
def create_announcement():
    data = request.json
    hack_code = data.get("hackCode")
    title = data.get("title")
    content = data.get("content")
    expiry_date = data.get("expiryDate")
    user_email = data.get("userEmail")

    if not hack_code or not title or not content or not expiry_date:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        expiry_datetime = datetime.fromisoformat(expiry_date.replace("Z", "+00:00"))
        if expiry_datetime <= datetime.now(timezone.utc):
            return jsonify({"error": "Expiry date must be in the future"}), 400
    except ValueError:
        return jsonify({"error": "Invalid expiry date format"}), 400

    announcement = {
        "id": str(uuid.uuid4()),
        "title": title,
        "content": content,
        "createdBy": user_email,
        "createdAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "expiryDate": expiry_date
    }

    result = hackathons.update_one(
        {"hackCode": hack_code},
        {"$push": {"announcements": announcement}}
    )

    if result.modified_count == 0:
        return jsonify({"error": "Hackathon not found"}), 404

    return jsonify({"message": "Announcement created successfully", "announcement": announcement}), 201


@app.route("/announcements", methods=["GET"])
def get_announcements():
    hack_code = request.args.get("hackCode")
    include_expired = request.args.get("includeExpired", "false").lower() == "true"

    if not hack_code:
        return jsonify({"error": "hackCode is required"}), 400

    hackathon = hackathons.find_one({"hackCode": hack_code}, {"announcements": 1, "_id": 0})
    if not hackathon:
        return jsonify({"error": "Hackathon not found"}), 404

    announcements = hackathon.get("announcements", [])

    if not include_expired:
        current_time = datetime.now(timezone.utc)
        active_announcements = []
        for announcement in announcements:
            try:
                expiry_datetime = datetime.fromisoformat(
                    announcement["expiryDate"].replace("Z", "+00:00")
                )
                if expiry_datetime > current_time:
                    active_announcements.append(announcement)
            except (ValueError, KeyError):
                continue
        announcements = active_announcements

    return jsonify({"announcements": announcements}), 200


@app.route("/grading", methods=["POST"])
@token_required
def grading():
    data = request.get_json(silent=True) or {}
    hack_code = data.get("hackCode")
    team_id = data.get("teamId")
    phase_id = data.get("phaseId")
    score = data.get("score")

    if not hack_code or not team_id or phase_id is None or score is None:
        return jsonify({"error": "hackCode, teamId, phaseId, and score are required"}), 400

    # Fetch hackathon
    hack = hackathons.find_one({"hackCode": hack_code})
    if not hack:
        return jsonify({"error": "Hackathon not found"}), 404

    # Find the team
    team = next((t for t in hack.get("registrations", []) if t["teamId"] == team_id), None)
    if not team:
        return jsonify({"error": "Team not found"}), 404

    # Ensure team has submissions
    if "submissions" not in team or not team["submissions"]:
        return jsonify({"error": "No submissions found for this team"}), 404

    # Find the submission for given phaseId
    submission = next((s for s in team["submissions"] if s["phaseId"] == phase_id), None)
    if not submission:
        return jsonify({"error": "Submission for this phase not found"}), 404

    # Attach/Update score
    if "score" not in submission:
        submission["score"] = score
    else:
        submission["score"] = score  # overwrite (if you only want first-time set, remove this line)

    # Save back
    hackathons.update_one(
        {"hackCode": hack_code, "registrations.teamId": team_id},
        {"$set": {"registrations.$": team}}
    )

    return jsonify({
        "message": "Score added successfully",
        "teamId": team_id,
        "phaseId": phase_id,
        "score": submission["score"]
    }), 200

@app.route("/eliminate", methods=["POST"])
def eliminate():
    hack_code = request.args.get("hackCode")
    phase_id = request.args.get("phaseId", type=int)
    data = request.get_json()
    cutoff_score = data.get("cutoff_score")

    if not hack_code or phase_id is None or cutoff_score is None:
        return jsonify({"error": "hackCode, phaseId, and cutoff_score required"}), 400

    # fetch hackathon
    hackathon = hackathons.find_one({"hackCode": hack_code})
    if not hackathon:
        return jsonify({"error": "Hackathon not found"}), 404

    updated_teams = {
        "active": [],
        "inactive": []
    }

    for team in hackathon.get("registrations", []):
        submissions = team.get("submissions", [])
        submission = next(
            (s for s in submissions if int(s.get("phaseId", -1)) == phase_id),
            None
        )
        score = submission.get("score") if submission else None

        if score is not None and score >= cutoff_score:
            team["status"] = "active"
            updated_teams["active"].append(team["teamId"])
        else:
            team["status"] = "inactive"
            updated_teams["inactive"].append(team["teamId"])

    # update registrations back in DB
    hackathons.update_one(
        {"hackCode": hack_code},
        {"$set": {"registrations": hackathon["registrations"]}}
    )

    return jsonify({
        "message": "Elimination completed",
        "cutoff_score": cutoff_score,
        "updatedTeams": updated_teams
    }), 200
@app.route("/publishresults", methods=["POST"])
@token_required
def publish_results():
    """
    Publish results for a hackathon (admin only).
    Expected JSON payload from frontend:
    {
        "eventName": "trial123 nice",
        "hackCode": "HACK-D5AE6861",
        "leaderboard": [
            {
                "teamId": "1cd0d454-3612-4c9b-9a43-b90b267db0dd",
                "teamName": "rv",
                "memberCount": 1,
                "phaseScores": [{...}, {...}],
                "totalScore": 13,
                "rank": 1
            },
            ...
        ],
        "publishedAt": "2025-08-20T10:44:03.547Z",
        "totalTeams": 3
    }
    """
    data = request.get_json(silent=True) or {}
    user_email = request.user["email"]
    
    hack_code = data.get("hackCode")
    if not hack_code:
        return jsonify({"error": "hackCode is required"}), 400
    
    # Verify user is admin of this hackathon
    hack = hackathons.find_one({"hackCode": hack_code})
    if not hack:
        return jsonify({"error": "Hackathon not found"}), 404
    
    if user_email not in hack.get("admins", []):
        return jsonify({"error": "Not authorized. Only admins can publish results."}), 403
    
    # Prepare results data with the exact structure from frontend
    results = {
        "eventName": data.get("eventName", ""),
        "hackCode": hack_code,
        "leaderboard": data.get("leaderboard", []),
        "totalTeams": data.get("totalTeams", 0),
        "publishedAt": data.get("publishedAt", datetime.now().isoformat() + "Z"),
        "publishedBy": user_email  # Adding who published the results
    }
    
    # Update the hackathon document in hackdb.hackathons collection
    try:
        result = hackathons.update_one(
            {"hackCode": hack_code},
            {"$set": {"results": results}}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to update hackathon with results"}), 500
        
        logger.info(f"Results published for hackathon {hack_code} by {user_email}")
        
        return jsonify({
            "message": "Results published successfully",
            "results": results
        }), 200
        
    except Exception as e:
        logger.error(f"Error publishing results: {str(e)}")
        return jsonify({"error": "Failed to publish results", "details": str(e)}), 500


@app.route("/results", methods=["GET"])
def get_results():
    """
    Get published results for a hackathon.
    Query params: ?hackCode=HACK-XXXX
    """
    hack_code = request.args.get("hackCode")
    
    if not hack_code:
        return jsonify({"error": "hackCode is required"}), 400
    
    # Find the hackathon in hackdb.hackathons collection
    hack = hackathons.find_one({"hackCode": hack_code}, {"_id": 0})
    if not hack:
        return jsonify({"error": "Hackathon not found"}), 404
    
    # Check if results exist
    if "results" not in hack:
        return jsonify({"error": "Results not published yet for this hackathon"}), 404
    
    return jsonify({
        "hackCode": hack_code,
        "results": hack["results"]
    }), 200

@app.route("/check-plagiarism", methods=["POST"])
def check_plagiarism():
    """Check a GitHub repository for plagiarism"""
    try:
        data = request.get_json(silent=True) or {}
        repo_url = data.get('repository_url')
        
        if not repo_url:
            return jsonify({"error": "repository_url is required"}), 400
        
        # Validate GitHub URL
        if 'github.com' not in repo_url:
            return jsonify({"error": "Only GitHub repositories are supported"}), 400
        
        # Initialize plagiarism checker with your GitHub token
        github_token = os.getenv('GITHUB_TOKEN', '')  # Use your existing token
        checker = PlagiarismChecker(github_token)
        
        # Run plagiarism check
        result = checker.check_repository(repo_url)
        
        return jsonify({
            "success": True,
            "data": result
        })
        
    except ValueError as e:
        return jsonify({
            "success": False,
            "error": "Invalid repository URL",
            "message": str(e)
        }), 400
        
    except Exception as e:
        logger.error(f"Plagiarism check failed: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Analysis failed",
            "message": str(e)
        }), 500
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
