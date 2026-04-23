"""Admin blueprint: storage systems, settings, certificates, tags, logs."""
from flask import Blueprint

bp = Blueprint('admin', __name__, url_prefix='/admin')

# Side-effect imports register routes on ``bp``.
from app.routes.admin import (  # noqa: E402
    auth,  # noqa: F401
    certificates,  # noqa: F401
    import_export,  # noqa: F401
    logs,  # noqa: F401
    pure1,  # noqa: F401
    settings_views,  # noqa: F401
    systems,  # noqa: F401
    tags,  # noqa: F401
)
