"""Every federation REST route is administrator-gated.

These endpoints expose federation topology (peer addresses, ports, group
mappings, cert paths) and peer state.  OpenTAKServer does not gate plugin
blueprints globally — Flask-Security only protects routes that carry a
decorator — so an undecorated route here is reachable by anyone who can
reach the OTS Flask app.

Guards the regression directly: before this, all three routes answered
unauthenticated.
"""
import pytest

flask = pytest.importorskip("flask")
pytest.importorskip("flask_security")

from flask import Flask  # noqa: E402


# (rule, method) for every route the blueprint is allowed to expose.
#
# Deliberately excludes any per-peer enable/disable route: the official
# Federation Hub has no such endpoint (outgoingEnabled is a policy property
# applied live by the broker), and our engine cannot re-apply peer state
# without a restart.  A route added here must also be given an auth decision.
EXPECTED_ROUTES = {
    ("/api/federation/status", "GET"),
    ("/api/federation/config", "GET"),
}


def _app_with_security(blueprint):
    """Minimal Flask app with Flask-Security initialised and no users.

    Flask-Security needs a real user model (fs_uniquifier since 4.0), so a
    throwaway in-memory SQLite datastore is built here.  No user is ever
    created, so every request in this module is anonymous by construction.
    """
    from flask_sqlalchemy import SQLAlchemy
    from flask_security import Security, SQLAlchemyUserDatastore
    from flask_security.models import fsqla_v3 as fsqla

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="test-only-not-a-credential",
        SECURITY_PASSWORD_SALT="test-only-not-a-credential",
        SQLALCHEMY_DATABASE_URI="sqlite://",
        WTF_CSRF_ENABLED=False,
        TESTING=True,
    )
    db = SQLAlchemy(app)
    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        __tablename__ = "role"

    class User(db.Model, fsqla.FsUserMixin):
        __tablename__ = "user"

    with app.app_context():
        db.create_all()

    Security(app, SQLAlchemyUserDatastore(db, User, Role))
    app.register_blueprint(blueprint)
    return app


@pytest.fixture(name="blueprint")
def _blueprint():
    from ots_federation.plugin import FederationPlugin

    plugin = FederationPlugin.__new__(FederationPlugin)
    plugin._build_blueprint()
    return plugin.blueprint


def _registered(blueprint):
    """Map endpoint-name -> (rule, methods) for the blueprint's routes."""
    app = Flask(__name__)
    app.register_blueprint(blueprint)
    out = {}
    for rule in app.url_map.iter_rules():
        if rule.endpoint.startswith("federation_plugin."):
            methods = rule.methods - {"HEAD", "OPTIONS"}
            out[rule.endpoint.split(".", 1)[1]] = (str(rule), methods)
    return out


def test_blueprint_exposes_only_the_expected_routes(blueprint):
    """A new route must be added to EXPECTED_ROUTES, forcing an auth decision."""
    found = {
        (rule, method)
        for rule, methods in _registered(blueprint).values()
        for method in methods
    }
    assert found == EXPECTED_ROUTES


@pytest.mark.parametrize("view_name", ["status", "config"])
def test_route_is_administrator_gated(blueprint, view_name):
    """Each view is wrapped by auth_required + roles_accepted.

    Flask-Security wraps the view function, so the original is reachable via
    the __wrapped__ chain.  A bare (undecorated) view has no __wrapped__ at
    all, which is exactly the state this test exists to catch.
    """
    app = Flask(__name__)
    app.register_blueprint(blueprint)
    view = app.view_functions[f"federation_plugin.{view_name}"]

    depth = 0
    fn = view
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
        depth += 1

    assert depth >= 2, (
        f"{view_name} is not wrapped by both auth_required and roles_accepted "
        f"(found {depth} decorator layer(s)) — it would answer unauthenticated"
    )


@pytest.mark.parametrize(
    ("rule", "method"),
    sorted(EXPECTED_ROUTES),
)
def test_unauthenticated_request_is_refused(blueprint, rule, method):
    """End-to-end: an anonymous request must not reach the handler.

    Flask-Security answers 401/403 for an unauthenticated caller (or 302 to a
    login view when one is configured).  Anything in the 2xx range means the
    handler ran and the guard is absent.
    """
    app = _app_with_security(blueprint)

    path = rule.replace("<name>", "somepeer")
    resp = app.test_client().open(path, method=method)

    assert resp.status_code >= 300, (
        f"{method} {path} returned {resp.status_code} to an anonymous caller — "
        "the handler executed without authentication"
    )
    assert resp.status_code in (301, 302, 401, 403), (
        f"{method} {path} returned unexpected {resp.status_code}"
    )
