import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import bleach
from bleach.css_sanitizer import CSSSanitizer
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from PIL import Image
from sqlalchemy import CheckConstraint, or_
from sqlalchemy.orm import joinedload
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from properties import (
    ALLOWED_CSS_PROPERTIES,
    BANNED_URLS,
    CURRENT_POLICY_VERSION,
    allowed_attributes,
    allowed_tags,
)

app = Flask(__name__)
app.secret_key = "your-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pastes.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
csrf = CSRFProtect(app)
app.config["UPLOAD_FOLDER"] = "static/profile_pics"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
db = SQLAlchemy(app)
app.jinja_env.finalize = lambda x: x if x is not None else ""

user_badges = db.Table(
    "user_badges",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("badge_id", db.Integer, db.ForeignKey("badge.id")),
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_picture = db.Column(db.String(120), nullable=True)
    bio = db.Column(db.String(500), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    custom_css = db.Column(db.String(1000), nullable=True)
    badges = db.relationship("Badge", secondary=user_badges, backref="users")
    privacy_policy = db.Column(db.Integer, nullable=False)
    pastes = db.relationship(
        "Paste", backref="user", cascade="all, delete", passive_deletes=True
    )

    __table_args__ = (
        CheckConstraint("LENGTH(bio) <= 500", name="bio_length_check"),
        CheckConstraint("LENGTH(custom_css) <= 1000", name="custom_css_length_check"),
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Paste(db.Model):
    id = db.Column(db.String(30), primary_key=True)
    content = db.Column(db.String(5000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    last_edited_at = db.Column(db.DateTime, nullable=True)
    published_at = db.Column(db.DateTime, nullable=True)
    views = db.Column(db.Integer, default=0)
    meta_description = db.Column(db.String(255), nullable=True)
    meta_image = db.Column(db.String(255), nullable=True)
    theme_color = db.Column(db.String(7), nullable=True)
    page_title = db.Column(db.String(255), nullable=True)
    favicon_url = db.Column(db.String(255), nullable=True)
    password_hash = db.Column(db.String(128), nullable=True)


class IPLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30))
    ip_address = db.Column(db.String(45))
    action = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=db.func.now())


class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(255))
    banned_at = db.Column(db.DateTime, default=db.func.now())


class BannedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True)
    reason = db.Column(db.String(255))
    banned_at = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship("User", backref="banned")


class InviteCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    used = db.Column(db.Boolean, default=False)
    used_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)

    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    creator = db.relationship(
        "User", foreign_keys=[creator_id], backref="created_invite_codes"
    )
    used_by_user = db.relationship(
        "User", foreign_keys=[used_by], backref="used_invite_codes"
    )


class Badge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))
    icon_url = db.Column(db.String(255))


class ClaimLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    claimed_at = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship("User", backref="claim_logs")


with app.app_context():
    db.create_all()

# -------- helpers ----------


def sanitize_css(css):
    css = re.sub(r"@import[^;]*;", "", css, flags=re.IGNORECASE)
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    declarations = css.split(";")
    sanitized_declarations = []

    for decl in declarations:
        decl = decl.strip()
        if not decl:
            continue
        if ":" not in decl:
            continue
        prop, value = decl.split(":", 1)
        prop = prop.strip().lower()
        value = value.strip()

        if re.search(r"expression|url\(", value, re.IGNORECASE):
            if prop == "background-image":
                pass
            else:
                continue

        if prop in ALLOWED_CSS_PROPERTIES:
            sanitized_declarations.append(f"{prop}: {value}")

    return "; ".join(sanitized_declarations)


class NoImportCSSSanitizer(CSSSanitizer):
    def sanitize_css_import(self, css):
        css = re.sub(r"@import[^;]*;", "", css, flags=re.IGNORECASE)
        return super().sanitize_css(css)


css_sanitizer_instance = NoImportCSSSanitizer(
    allowed_css_properties=ALLOWED_CSS_PROPERTIES
)
css_sanitizer_instance = CSSSanitizer(allowed_css_properties=ALLOWED_CSS_PROPERTIES)


def extract_css_declarations(css_block):
    match = re.search(r"\{([^}]*)\}", css_block, re.DOTALL)
    if match:
        return match.group(1)
    return css_block


def sanitize_content(content):
    return bleach.clean(
        content,
        tags=allowed_tags,
        attributes=allowed_attributes,
        css_sanitizer=css_sanitizer_instance,
        strip=True,
    )


def is_ip_banned(ip):
    return BannedIP.query.filter_by(ip_address=ip).first() is not None


def is_user_banned(user_id):
    return BannedUser.query.filter_by(user_id=user_id).first() is not None


def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].split(",")[0]
    else:
        ip = request.remote_addr
    return ip


def log_ip(action):
    user_id = session.get("user_id")
    if not user_id:
        return

    user = User.query.get(user_id)
    if not user:
        return

    ip = get_client_ip()
    ip_log = IPLog(username=user.username, ip_address=ip, action=action)
    db.session.add(ip_log)
    db.session.commit()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get("user_id"))
        if not user or not user.is_admin:
            abort(403)  # FORBIDDEEN
        return f(*args, **kwargs)

    return decorated_function


@app.errorhandler(400)
def request_failed(e):
    return render_template("errors/400.html"), 400


@app.errorhandler(401)
def authorization_failed(e):
    return render_template("errors/401.html"), 401


@app.errorhandler(403)
def access_denied(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def page_not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def csrf_token(e):
    return render_template("errors/500.html"), 500


def get_form_value(key):
    value = request.form.get(key)
    return value if value is not None else ""


# -------- app routes --------


@app.route("/", methods=["GET", "POST"])
def index():
    ip = get_client_ip()
    if is_ip_banned(ip):
        return jsonify({"success": False, "error": "your ip has been banned!"}), 200

    if request.method == "POST":
        if "user_id" not in session:
            return jsonify({"success": False, "error": "please log in to submit!"}), 200

        user_id = session["user_id"]
        one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)
        claim_count = (
            Paste.query.filter_by(user_id=user_id)
            .filter(Paste.published_at >= one_day_ago)
            .count()
        )

        if claim_count >= 10:
            return jsonify(
                {"success": False, "error": "you have reached the daily claim limit."}
            ), 200

        raw_content = request.form.get("content")
        if raw_content is None:
            return jsonify({"success": False, "error": "no content provided!"}), 200

        content = sanitize_content(raw_content)
        if not content:
            return jsonify(
                {"success": False, "error": "content is empty after sanitization."}
            ), 200

        custom_id = request.form.get("custom_id", "").strip()

        if custom_id:
            if not re.match(r"^[a-zA-Z0-9_-]+$", custom_id):
                return jsonify(
                    {"success": False, "error": "invalid url format/characters"}
                ), 200
            if custom_id in BANNED_URLS:
                return jsonify({"success": False, "error": "this url is banned."}), 200
            if Paste.query.get(custom_id):
                return jsonify(
                    {"success": False, "error": "that url is already taken!"}
                ), 200
            paste_id = custom_id
        else:
            import uuid

            while True:
                paste_id = uuid.uuid4().hex[:8]
                if not Paste.query.get(paste_id):
                    break

        new_paste = Paste(
            id=paste_id,
            content=content,
            user_id=user_id,
            published_at=datetime.now(timezone.utc),
            last_edited_at=datetime.now(timezone.utc),
        )
        db.session.add(new_paste)
        db.session.commit()

        return jsonify(
            {"success": True, "redirect_url": url_for("view_paste", paste_id=paste_id)}
        )

    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        invite_code_input = request.form.get("invite_code", "").strip()

        if invite_code_input:
            invite = InviteCode.query.filter_by(
                code=invite_code_input, used=False
            ).first()
            if not invite:
                error = "invalid or already used invite code!"
                return render_template("register.html", error=error)
        else:
            error = "invite code is required!"
            return render_template("register.html", error=error)

        if User.query.filter_by(username=username).first():
            error = "username already exists!!"
        else:
            user = User(username=username, privacy_policy=CURRENT_POLICY_VERSION)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            if invite:
                invite.used = True
                invite.used_by = user.id
                invite.used_at = db.func.now()
                db.session.commit()

            session["user_id"] = user.id

            return redirect(url_for("index"))

    return render_template("user/register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    ip = get_client_ip()
    if is_ip_banned(ip):
        return "your ip has been banned!", 403
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            log_ip("login")
            return redirect(url_for("index"))
        else:
            error = "invalid credentials."
            log_ip("failed login")
    return render_template("user/login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("index"))


# ------------ pastes ------------


@app.route("/<paste_id>")
def view_paste(paste_id):
    paste = Paste.query.get(paste_id)
    if not paste:
        abort(404)

    if paste.password_hash:
        if not session.get(f"paste_{paste_id}_unlocked"):
            return redirect(url_for("view_protected_paste", paste_id=paste_id))

    user_id = session.get("user_id")
    user = User.query.get(user_id)
    visitor_username = None
    if "user_id" in session:
        current_user = User.query.get(session["user_id"])
        if current_user:
            visitor_username = current_user.username

    log_ip(f"{visitor_username} viewed paste {paste_id}")

    safe_content = sanitize_content(paste.content)

    cookie_key = "viewed_paste"

    response = make_response(
        render_template(
            "paste/view_paste.html",
            paste=paste,
            current_user=user,
            safe_content=safe_content,
            published_at=paste.published_at,
            last_edited_at=paste.last_edited_at,
            logged_in=("user_id" in session),
        )
    )

    if not request.cookies.get(cookie_key):
        paste.views = (paste.views or 0) + 1
        db.session.commit()

        response.set_cookie(
            cookie_key, "true", max_age=60 * 60 * 24 * 7, path=f"/{paste_id}"
        )

    return response


@app.route("/edit/<paste_id>", methods=["GET", "POST"])
@login_required
def edit_paste(paste_id):
    paste = Paste.query.get(paste_id)
    if not paste:
        abort(404)

    user = User.query.get(session.get("user_id"))
    if user is None:
        return redirect(url_for("login"))

    if paste.user_id != user.id and not user.is_admin:
        abort(403)

    if request.method == "POST":
        raw_content = request.form.get("content")
        if raw_content is None:
            abort(400)

        sanitized_content = sanitize_content(raw_content)
        if sanitized_content is None:
            sanitized_content = ""

        paste.content = sanitized_content
        paste.last_edited_at = datetime.now(timezone.utc)

        def get_form_value(key):
            value = request.form.get(key)
            if value is None:
                return ""
            value_stripped = value.strip()
            if value_stripped.lower() == "none" or value_stripped == "":
                return ""
            return value

        paste.meta_description = get_form_value("meta_description")
        paste.meta_image = get_form_value("meta_image")
        paste.theme_color = get_form_value("theme_color")
        paste.page_title = get_form_value("page_title")
        paste.favicon_url = get_form_value("favicon_url")

        db.session.commit()

        return redirect(url_for("view_paste", paste_id=paste_id))

    for attr in [
        "meta_description",
        "meta_image",
        "theme_color",
        "page_title",
        "favicon_url",
    ]:
        value = getattr(paste, attr)
        if value is None or value.lower() == "none":
            setattr(paste, attr, "")

    return render_template("paste/edit_paste.html", paste=paste)


@app.route("/update_password/<paste_id>", methods=["GET", "POST"])
@login_required
def update_paste_password(paste_id):
    paste = Paste.query.get(paste_id)
    if not paste:
        return "paste not found.", 404

    current_user = User.query.get(session.get("user_id"))
    if not current_user:
        return redirect(url_for("login"))

    if paste.user_id != current_user.id and not current_user.is_admin:
        return "you don't have permission.", 403

    if request.method == "POST":
        new_password = request.form.get("new_password")
        if new_password:
            paste.password_hash = generate_password_hash(new_password)
            db.session.commit()
            return redirect(url_for("view_paste", paste_id=paste_id))
        else:
            return jsonify(success=False, error="password cannot be empty.")

    return render_template("paste/update_password.html", paste=paste)


@app.route("/remove_paste_password/<paste_id>", methods=["POST"])
def remove_paste_password(paste_id):
    paste = Paste.query.get_or_404(paste_id)

    paste.password = None

    try:
        db.session.commit()
        return redirect(url_for("view_paste", paste_id=paste_id))
    except Exception as e:
        db.session.rollback()
        return jsonify(
            success=False, error=f"error removing password for {paste_id}: {e}"
        )


@app.route("/<paste_id>/protected", methods=["GET", "POST"])
def view_paste_protected(paste_id):
    paste = Paste.query.get(paste_id)
    if not paste:
        abort(404)

    if not paste.password_hash:
        return redirect(url_for("view_paste", paste_id=paste_id))

    if request.method == "POST":
        entered_password = request.form.get("password")
        if entered_password and check_password_hash(
            paste.password_hash, entered_password
        ):
            session[f"paste_{paste_id}_unlocked"] = True
            return redirect(url_for("view_paste", paste_id=paste_id))
        else:
            error = "Incorrect password. Please try again."
            return render_template("paste/password_prompt.html", error=error)

    if session.get(f"paste_{paste_id}_unlocked"):
        return redirect(url_for("view_paste", paste_id=paste_id))

    return render_template("paste/password_prompt.html")


@app.route("/<paste_id>/protected", methods=["GET", "POST"])
def view_protected_paste(paste_id):
    paste = Paste.query.get(paste_id)
    if not paste:
        abort(404)

    if not paste.password_hash:
        return redirect(url_for("view_paste", paste_id=paste_id))

    if request.method == "POST":
        entered_password = request.form.get("password")
        if entered_password and check_password_hash(
            paste.password_hash, entered_password
        ):
            session[f"paste_{paste_id}_unlocked"] = True
            return redirect(url_for("view_paste", paste_id=paste_id))
        else:
            error = "incorrect password. please try again."
            return render_template("paste/password_prompt.html", error=error)

    if session.get(f"paste_{paste_id}_unlocked"):
        return redirect(url_for("view_paste", paste_id=paste_id))

    return render_template("paste/password_prompt.html")


@app.route("/transfer/<paste_id>", methods=["GET"])
@login_required
def transfer_ownership(paste_id):
    paste = Paste.query.get(paste_id)
    if not paste:
        return "paste not found.", 404

    current_user_obj = User.query.get(session.get("user_id"))
    if current_user_obj is None:
        return redirect(url_for("login"))

    if paste.user_id != current_user_obj.id and not current_user_obj.is_admin:
        return "you don't have permission.", 403

    return render_template("paste/transfer_paste.html", paste=paste)


@app.route("/transfer/<paste_id>", methods=["POST"])
@login_required
def handle_transfer(paste_id):
    paste = Paste.query.get(paste_id)
    if not paste:
        return jsonify(success=False, error="paste not found!"), 404

    current_user_obj = User.query.get(session.get("user_id"))
    if current_user_obj is None:
        return jsonify(success=False, error="user not logged in!!!"), 401

    if paste.user_id != current_user_obj.id and not current_user_obj.is_admin:
        return jsonify(success=False, error="you don't have the perms for this"), 403

    new_owner_username = request.form.get("new_owner")
    new_owner = User.query.filter_by(username=new_owner_username).first()
    if not new_owner:
        return jsonify(
            success=False, error="new owner ...not found? check your spelling"
        ), 400

    if new_owner.id == current_user_obj.id:
        return jsonify(
            success=False,
            error="you cannot transfer the paste to yourself.",
        ), 400

    paste.user_id = new_owner.id
    db.session.commit()

    return jsonify(success=True)


@app.route("/<paste_id>/delete", methods=["POST"])
@login_required
def delete_paste(paste_id):
    paste = Paste.query.get(paste_id)
    if not paste:
        abort(404)

    user = User.query.get(session.get("user_id"))
    if user is None:
        return redirect(url_for("login"))

    if paste.user_id != user.id and not user.is_admin:
        abort(403)
    paste.is_deleted = True
    db.session.delete(paste)
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/<paste_id>/report")
@login_required
def report(paste_id):
    paste = Paste.query.get(paste_id)
    if paste is None:
        abort(404)
    return render_template("paste/report.html", paste=paste)


@app.route("/<paste_id>/report", methods=["POST"])
def report_post(paste_id):
    paste = Paste.query.get(paste_id)
    if paste is None:
        abort(404)
    if not current_user.is_authenticated:
        abort(401)

    if paste.user_id != current_user.id:
        abort(403)

    paste.user_id = None
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/<paste_id>/reclaim")
@login_required
def reclaim(paste_id):
    paste = Paste.query.get(paste_id)
    if paste is None:
        abort(404)
    return render_template("paste/reclaim.html", paste=paste)


@app.route("/<paste_id>/reclaim", methods=["POST"])
def reclaim_post(paste_id):
    paste = Paste.query.get(paste_id)
    if paste is None:
        abort(404)
    if paste.user_id != current_user.id:
        abort(403)
    paste.user_id = None
    db.session.commit()
    return redirect(url_for("dashboard", paste=paste))


@app.route("/extras/<paste_id>")
@login_required
def paste_extras(paste_id):
    paste = Paste.query.get(paste_id)
    if paste is None:
        abort(404)
    return render_template("paste/paste_extras.html", paste=paste)


#  ------ user side --------


@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile() -> ResponseReturnValue:
    user = User.query.get(session.get("user_id"))
    if user is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        custom_css_input = request.form.get("custom_css", "").strip()
        declarations = extract_css_declarations(custom_css_input)
        sanitized_declarations = sanitize_css(declarations)
        match = re.search(r"\{[^}]*\}", custom_css_input)
        if match:
            full_css = (
                custom_css_input[: match.start()]
                + "{"
                + sanitized_declarations
                + "}"
                + custom_css_input[match.end() :]
            )
        else:
            full_css = custom_css_input
        user.custom_css = full_css

        bio_html = request.form.get("bio", "").strip()
        user.bio = bio_html

        file = request.files.get("profile_picture")
        if file and file.filename:
            filename = secure_filename(file.filename)
            webp_filename = f"user_{user.id}.webp"
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            webp_filepath = os.path.join(app.config["UPLOAD_FOLDER"], webp_filename)
            file.save(filepath)
            try:
                img = Image.open(filepath)
                img.save(webp_filepath, "WEBP")
                os.remove(filepath)
                old_pfp = user.profile_picture
                if old_pfp and old_pfp != webp_filename:
                    old_pfp_path = os.path.join(app.config["UPLOAD_FOLDER"], old_pfp)
                    if os.path.exists(old_pfp_path):
                        os.remove(old_pfp_path)
                user.profile_picture = webp_filename
            except Exception as e:
                print(f"Error converting image: {e}")
                user.profile_picture = webp_filename

        new_username = request.form.get("username", "").strip()
        if new_username and new_username != user.username:
            existing_user = User.query.filter_by(username=new_username).first()
            if not existing_user:
                user.username = new_username
            else:
                error_message = "username already exists.. please choose a different one.ill make this nicer later."
                return render_template(
                    "user/edit_profile.html", user=user, error=error_message
                )

        db.session.commit()
        return redirect(url_for("profile", username=user.username))
    return render_template("user/edit_profile.html", user=user)


@app.route("/profile/<username>", methods=["GET", "POST"])
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()

    visitor_username = None
    if "user_id" in session:
        current_user = User.query.get(session["user_id"])
        if current_user:
            visitor_username = current_user.username

    log_ip(f"{visitor_username} viewed profile of {user.username}")

    is_owner = session.get("user_id") == user.id

    if request.method == "POST":
        if not is_owner:
            return redirect(url_for("profile", username=user.username))

        bio = request.form.get("bio", "")
        user.bio = bio

        file = request.files.get("profile_picture")
        if file and file.filename:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            user.profile_picture = filename

        db.session.commit()
        return redirect(url_for("profile", username=user.username))

    return render_template(
        "user/profile.html",
        user=user,
        is_owner=is_owner,
        visitor_username=visitor_username,
        profile_owner_username=user.username,
    )


@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session.get("user_id"))
    if user is None:
        session.pop("user_id", None)
        return redirect(url_for("login"))

    search_query = request.args.get("search", "")
    page = int(request.args.get("page", 1))
    per_page = 10

    pastes_query = Paste.query.filter_by(user_id=user.id)

    if search_query:
        pastes_query = pastes_query.filter(
            or_(
                Paste.id.cast(db.String).contains(search_query),
                Paste.content.contains(search_query),
            )
        )

    total = pastes_query.count()
    user_pastes = pastes_query.offset((page - 1) * per_page).limit(per_page).all()

    return render_template(
        "user/dashboard.html",
        pastes=user_pastes,
        page=page,
        total=total,
        per_page=per_page,
        search=search_query,
    )


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user = User.query.get(session.get("user_id"))
    if user is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not user.check_password(current_password):
            return jsonify(
                {"success": False, "error": "current password is incorrect."}
            )

        if new_password != confirm_password:
            return jsonify({"success": False, "error": "new passwords do not match."})

        user.set_password(new_password)
        db.session.commit()
        return jsonify(
            {
                "success": True,
                "redirect_url": url_for("profile", username=user.username),
            }
        )

    return render_template("user/change_password.html")


@app.route("/accept_terms", methods=["GET", "POST"])
def accept_terms():
    if request.method == "POST":
        if g.current_user:
            g.current_user.privacy_policy = CURRENT_POLICY_VERSION
            db.session.commit()
        return redirect(url_for("index"))
    return render_template("accept_terms.html")


@app.route("/delete_account", methods=["GET", "POST"])
@login_required
def delete_account():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if user is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        password_input = request.form.get("password", "").strip()
        if not check_password_hash(user.password_hash, password_input):
            error = "incorrect password."
            return render_template("user/delete_account.html", user=user, error=error)

        try:
            for paste in user.pastes:
                db.session.delete(paste)
            db.session.flush()
            db.session.delete(user)

            db.session.commit()
        except Exception as e:
            print("Error during deletion:", e)
            db.session.rollback()
            error = "an error occurred. please try again later!"
            return render_template("user/delete_account.html", user=user, error=error)

        session.clear()
        return redirect(url_for("index"))

    return render_template("user/delete_account.html", user=user)


# ------- admin --------


@app.route("/admin")
@admin_required
def admin_panel():
    return render_template("admin/admin.html")


@app.route("/admin/assign_badge/<int:user_id>/<int:badge_id>", methods=["POST"])
@admin_required
def assign_badge(user_id, badge_id):
    user = User.query.get_or_404(user_id)
    badge = Badge.query.get_or_404(badge_id)
    if badge not in user.badges:
        user.badges.append(badge)
        db.session.commit()
    return redirect(url_for("users"))


@app.route("/admin/remove_badge/<int:user_id>/<int:badge_id>", methods=["POST"])
@admin_required
def remove_badge(user_id, badge_id):
    user = User.query.get_or_404(user_id)
    badge = Badge.query.get_or_404(badge_id)
    if badge in user.badges:
        user.badges.remove(badge)
        db.session.commit()
    return redirect(url_for("users"))


@app.route("/admin/pastes")
@admin_required
def pastes():
    search_query = request.args.get("search", "")
    page = int(request.args.get("page", 1))
    per_page = 10

    query = Paste.query.order_by(Paste.published_at.desc())

    if search_query:
        query = query.filter(Paste.content.ilike(f"%{search_query}%"))

    total = query.count()
    pastes = query.offset((page - 1) * per_page).limit(per_page).all()

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "admin/pastes.html",
        pastes=pastes,
        page=page,
        total_pages=total_pages,
        search=search_query,
    )


@app.route("/admin/ip_logs")
@admin_required
def ip_logs():
    search_query = request.args.get("search", "", type=str)
    page = request.args.get("page", 1, type=int)
    per_page = 10

    query = IPLog.query

    if search_query:
        query = query.filter(
            or_(
                IPLog.username.ilike(f"%{search_query}%"),
                IPLog.ip_address.ilike(f"%{search_query}%"),
            )
        )

    total = query.count()
    total_pages = (total + per_page - 1) // per_page

    logs = (
        query.order_by(IPLog.timestamp.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return render_template(
        "admin/ip_logs.html",
        logs=logs,
        page=page,
        total_pages=total_pages,
        search=search_query,
    )


@app.route("/admin/user_ip_logs/<username>")
@admin_required
def user_ip_logs(username):
    logs = (
        IPLog.query.filter_by(username=username).order_by(IPLog.timestamp.desc()).all()
    )
    return render_template("admin/user_ip_logs.html", logs=logs, username=username)


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        user_id = int(request.form.get("user_id"))
        badge_id = int(request.form.get("badge_id"))
        user = User.query.get_or_404(user_id)
        badge = Badge.query.get_or_404(badge_id)
        if badge not in user.badges:
            user.badges.append(badge)
            db.session.commit()
        return redirect(url_for("users", page=request.args.get("page", 1)))

    search_query = request.args.get("search", "", type=str)
    page = request.args.get("page", 1, type=int)
    per_page = 10

    query = User.query
    if search_query:
        query = query.filter(User.username.ilike(f"%{search_query}%"))

    total = query.count()
    total_pages = (total + per_page - 1) // per_page

    users = (
        query.order_by(User.username)
        .offset((page - 1) * per_page)
        .limit(per_page)
        .options(joinedload(User.badges))
        .all()
    )

    users_with_ban_status = []
    for user in users:
        users_with_ban_status.append(
            {
                "user": user,
                "banned": bool(BannedUser.query.filter_by(user_id=user.id).first()),
                "badges": user.badges,
            }
        )

    badges = Badge.query.all()

    return render_template(
        "admin/users.html",
        users=users_with_ban_status,
        badges=badges,
        page=page,
        total_pages=total_pages,
        search=search_query,
    )


@app.route("/admin/ban_ip", methods=["POST"])
@admin_required
def ban_ip():
    ip_address = request.form["ip_address"]
    reason = request.form.get("reason", "")
    if not is_ip_banned(ip_address):
        ban = BannedIP(ip_address=ip_address, reason=reason)
        db.session.add(ban)
        db.session.commit()
    return redirect(url_for("ip_logs"))


@app.route("/admin/unban_ip/<ip_address>")
@admin_required
def unban_ip(ip_address):
    ban = BannedIP.query.filter_by(ip_address=ip_address).first()
    if ban:
        db.session.delete(ban)
        db.session.commit()
    return redirect(url_for("ip_logs"))


@app.route("/admin/ban_user/<int:user_id>", methods=["POST"])
@admin_required
def ban_user(user_id):
    reason = request.form.get("reason", "")
    if not is_user_banned(user_id):
        ban = BannedUser(user_id=user_id, reason=reason)
        db.session.add(ban)
        db.session.commit()
    return redirect(url_for("users"))


@app.route("/admin/unban_user/<int:user_id>")
@admin_required
def unban_user(user_id):
    ban = BannedUser.query.filter_by(user_id=user_id).first()
    if ban:
        db.session.delete(ban)
        db.session.commit()
    return redirect(url_for("users"))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        for paste in user.pastes:
            db.session.delete(paste)
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for("users"))


@app.route("/admin/generate_invite", methods=["GET", "POST"])
@admin_required
def generate_invite():
    if request.method == "POST":
        code = secrets.token_hex(8)
        invite = InviteCode(code=code, creator_id=session["user_id"])
        db.session.add(invite)
        db.session.commit()
        return render_template("admin/generated_invite.html", code=code)
    return render_template("admin/generate_invite.html")


@app.route("/admin/invite_codes")
@admin_required
def invite_codes():
    return render_template("admin/invite_codes.html")


@app.route("/admin/all_invite_codes")
@admin_required
def all_invite_codes():
    codes = InviteCode.query.order_by(InviteCode.created_at.desc()).all()
    return render_template("admin/all_invite_codes.html", codes=codes)


@app.route("/admin/delete_invite_code/<int:code_id>", methods=["POST"])
@admin_required
def delete_invite_code(code_id):
    code = InviteCode.query.get_or_404(code_id)
    db.session.delete(code)
    db.session.commit()
    return redirect(url_for("all_invite_codes"))


@app.context_processor
def utility_processor():
    def is_ip_banned(ip):
        return BannedIP.query.filter_by(ip_address=ip).first() is not None

    def sanitize_content_for_template(content):
        return sanitize_content(content)

    return dict(
        is_ip_banned=is_ip_banned, sanitize_content=sanitize_content_for_template
    )


@app.before_request
def load_user():
    g.current_user = None
    if "user_id" in session:
        g.current_user = User.query.get(session["user_id"])


@app.before_request
def check_privacy_policy():
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        if user and user.privacy_policy != CURRENT_POLICY_VERSION:
            if request.endpoint != "accept_terms":
                return redirect(url_for("accept_terms"))


@app.context_processor
def inject_user():
    current_user = getattr(g, "current_user", None)
    return dict(current_user=current_user)


@app.template_filter("nice_date")
def nice_date_filter(value):
    from datetime import datetime

    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return value
    elif isinstance(value, datetime):
        dt = value
    else:
        return value
    return dt.strftime("%B %d, %Y at %I:%M %p")


if __name__ == "__main__":
    app.run(debug=True, port=5001)
