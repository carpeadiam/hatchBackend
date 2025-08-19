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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
