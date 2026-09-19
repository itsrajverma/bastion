"""Shared, tightly constrained argument types for tools (invariant 4)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

#: Services Bastion may inspect or restart. A closed enum, never free text.
#: The last five are the units provided by the package catalog (tools/packages.py).
Service = Literal[
    "nginx",
    "gunicorn",
    "celery",
    "postgresql",
    "apache2",
    "mysql",
    "mariadb",
    "redis-server",
    "memcached",
]
SERVICES: tuple[str, ...] = (
    "nginx",
    "gunicorn",
    "celery",
    "postgresql",
    "apache2",
    "mysql",
    "mariadb",
    "redis-server",
    "memcached",
)

DOMAIN_PATTERN = r"^[a-z0-9.-]+$"

#: A DNS name for certbot: lowercase letters, digits, dots, hyphens only.
Domain = Annotated[
    str,
    Field(
        pattern=DOMAIN_PATTERN,
        min_length=3,
        max_length=253,
        description="Fully qualified domain name, lowercase, e.g. app.example.com",
    ),
]

#: Linux pid_max is 4194304 (2^22).
Pid = Annotated[int, Field(ge=1, le=4_194_304, description="Process id")]

ProcessLimit = Annotated[int, Field(ge=1, le=25, description="Max rows to return (1-25)")]
QueryLimit = Annotated[int, Field(ge=1, le=20, description="Max rows to return (1-20)")]
LogLines = Annotated[int, Field(ge=1, le=500, description="Number of log lines (1-500)")]


def validate_domain(domain: str) -> str:
    """Extra structural checks beyond the regex (labels, dots, hyphens)."""
    if domain.startswith(".") or domain.endswith(".") or ".." in domain:
        raise ValueError("domain has an empty label")
    if "." not in domain:
        raise ValueError("domain must contain at least one dot")
    for label in domain.split("."):
        if len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError(f"invalid domain label {label!r}")
    return domain


#: Software Bastion may install. A closed enum that maps to fixed apt package
#: lists in :mod:`bastion.tools.packages`; there is no free-text package name.
Package = Literal[
    "nginx",
    "apache",
    "php",
    "python",
    "django",
    "nodejs",
    "mysql",
    "mariadb",
    "postgresql",
    "redis",
    "memcached",
    "certbot",
]
PACKAGES: tuple[str, ...] = (
    "nginx",
    "apache",
    "php",
    "python",
    "django",
    "nodejs",
    "mysql",
    "mariadb",
    "postgresql",
    "redis",
    "memcached",
    "certbot",
)
