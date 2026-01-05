from app import (
    CURRENT_POLICY_VERSION,
    Badge,
    User,
    app,
    db,
)


def create_admin(username, password):
    with app.app_context():
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User '{username}' already exists.")
            return
        admin_user = User(
            username=username, is_admin=True, privacy_policy=CURRENT_POLICY_VERSION
        )
        admin_user.set_password(password)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{username}' created successfully.")


if __name__ == "__main__":
    username = "admin"
    password = "password"
    create_admin(username, password)

with app.app_context():
    badges = [
        {
            "name": "staff",
            "description": "site staff member",
            "icon_url": "/static/icons/staff.svg",
        },
        {
            "name": "beta tester",
            "description": "participated in beta testing",
            "icon_url": "/static/icons/beta.svg",
        },
        {
            "name": "contributor",
            "description": "contributed content or code",
            "icon_url": "/static/icons/contributor.svg",
        },
        {
            "name": "warn",
            "description": "warned for something bad",
            "icon_url": "/static/icons/warn.svg",
        },
    ]
    for badge in badges:
        if not Badge.query.filter_by(name=badge["name"]).first():
            db.session.add(Badge(**badge))
            print(f"added badge: {badge['name']}")
    db.session.commit()
