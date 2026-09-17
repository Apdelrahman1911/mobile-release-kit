"""Pure workflow-caller bytes and the closed desktop caller roster.

No template discovery, filesystem, environment, transaction or remote authority
lives here. Fixed path strings are not custody of those files. A syntactically
pinned reference is not a resolved or trusted Git commit. Callers retain their
own input/output budgets and resource origin admission.
"""
from __future__ import annotations

import re

from .errors import ValidationError

MAX_TEMPLATE_BYTES = 1024 * 1024
TOOLING_REPOSITORY_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?"
)
SHA_PLACEHOLDER = "__MOBILE_RELEASE_KIT_SHA__"
REPOSITORY_PLACEHOLDER = "__MOBILE_RELEASE_KIT_REPOSITORY__"
GITHUB_WORKFLOWS = (
    ("preflight", ".github/workflows/mobile-preflight.yml"),
    ("candidate", ".github/workflows/mobile-candidate.yml"),
    ("external-testing", ".github/workflows/mobile-external-testing.yml"),
    ("production-submit", ".github/workflows/mobile-production-submit.yml"),
)


class MissingWorkflowPlaceholder(ValidationError):
    """A caller template omits at least one required literal pin marker."""


def normalize_tooling_reference(repository: object, sha: object) -> tuple[str, str]:
    """Retain CLI init's grammar, diagnostic order and SHA normalization."""
    if type(sha) is not str or re.fullmatch(r"[0-9A-Fa-f]{40}", sha) is None:
        raise ValidationError("--tooling-sha full commit is required to install workflow callers")
    if type(repository) is not str or TOOLING_REPOSITORY_RE.fullmatch(repository) is None:
        raise ValidationError("--tooling-repository must be a safe GitHub OWNER/REPO coordinate")
    return repository, sha.lower()


def pinned_schema_reference(repository: object, sha: object) -> str:
    """Informational only: do not fetch this reference or treat it as authority."""
    repository, sha = normalize_tooling_reference(repository, sha)
    return f"https://raw.githubusercontent.com/{repository}/{sha}/schemas/project.schema.json"


def render_workflow_caller(template: bytes, repository: object, sha: object) -> bytes:
    """Literal replacement only, preserving expressions and every other byte.

    The CLI already admits at most 1 MiB before calling this function. Desktop
    resources and generated output have separately stricter fixed budgets.
    """
    repository, sha = normalize_tooling_reference(repository, sha)
    if type(template) is not bytes:
        raise ValidationError("workflow caller template must be UTF-8")
    if len(template) > MAX_TEMPLATE_BYTES:
        raise ValidationError("workflow caller template exceeds 1 MiB")
    try:
        rendered = template.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError("workflow caller template must be UTF-8") from error
    replacements = ((SHA_PLACEHOLDER, sha), (REPOSITORY_PLACEHOLDER, repository))
    if any(marker not in rendered for marker, _ in replacements):
        raise MissingWorkflowPlaceholder("workflow caller template lacks required placeholder(s)")
    for marker, replacement in replacements:
        rendered = rendered.replace(marker, replacement)
    return rendered.encode("utf-8")
