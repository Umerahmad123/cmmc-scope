"""
GitHub Collector — cmmc_scope/collectors/github.py

Responsible for all interactions with the GitHub API via PyGithub.
Returns raw data structures only — zero compliance logic belongs here.

CMMC Control targeted: CM.L2-3.4.1 (Baseline Configuration / Change Control)
NIST SP 800-171 Reference: 3.4.1
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from github import Auth, Github, GithubException
from github.Branch import Branch
from github.Repository import Repository

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Transfer Objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BranchProtectionDetails:
    """
    Immutable record of the branch-protection configuration for a single
    branch on a GitHub repository.

    All boolean flags correspond directly to the GitHub Branch Protection API
    response fields so that nothing is inferred or interpreted here.
    """

    repo_full_name: str          # e.g. "acme-corp/my-service"
    branch_name: str             # e.g. "main"
    protection_enabled: bool     # True if *any* protection rule is active

    # Pull-request / review requirements ─ the specific sub-controls
    # evaluated by CM.L2-3.4.1.
    required_pr_reviews: bool           # at least one review required before merge
    required_approving_review_count: int
    dismiss_stale_reviews: bool
    require_code_owner_reviews: bool

    # Additional protection attributes — useful context for auditors.
    require_status_checks: bool
    enforce_admins: bool
    allow_force_pushes: bool
    allow_deletions: bool


@dataclass
class BranchProtectionResult:
    """Container for the full branch-protection collection run."""

    repo_full_name: str
    default_branch: str
    details: BranchProtectionDetails | None = None
    collection_errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_protection_details(
    repo: Repository,
    branch: Branch,
) -> BranchProtectionDetails:
    """
    Fetch the full branch-protection ruleset for *branch* and map it into a
    BranchProtectionDetails DTO.

    Requires that the authenticated token has at minimum the repo scope (for
    private repos) or be a collaborator with admin rights to read protection
    rules.
    """
    protection = branch.get_protection()

    # Pull-request review requirement block ─ may be None when not configured.
    pr_reviews = protection.required_pull_request_reviews
    required_pr_reviews = pr_reviews is not None
    required_approving_review_count = (
        pr_reviews.required_approving_review_count if pr_reviews else 0
    )
    dismiss_stale = pr_reviews.dismiss_stale_reviews if pr_reviews else False
    require_code_owners = pr_reviews.require_code_owner_reviews if pr_reviews else False

    # Status-check requirement block — may be None.
    status_checks = protection.required_status_checks
    require_status_checks = status_checks is not None

    return BranchProtectionDetails(
        repo_full_name=repo.full_name,
        branch_name=branch.name,
        protection_enabled=True,  # We only reach this path when protection exists.
        required_pr_reviews=required_pr_reviews,
        required_approving_review_count=required_approving_review_count,
        dismiss_stale_reviews=dismiss_stale,
        require_code_owner_reviews=require_code_owners,
        require_status_checks=require_status_checks,
        enforce_admins=protection.enforce_admins.enabled,
        allow_force_pushes=protection.allow_force_pushes.enabled,
        allow_deletions=protection.allow_deletions.enabled,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def collect_branch_protection(
    github_token: str,
    repo_full_name: str,
    branch_name: str | None = None,
) -> BranchProtectionResult:
    """
    Collect branch-protection configuration for the target repository.

    Args:
        github_token:   A GitHub Personal Access Token (classic or fine-grained)
                        with at minimum `repo` scope for private repositories, or
                        `public_repo` for public ones.
        repo_full_name: The full repository identifier in the format
                        ``owner/repo`` (e.g. ``acme-corp/my-service``).
        branch_name:    The branch to inspect.  When None the repository's
                        default branch (typically ``main`` or ``master``) is
                        used automatically.

    Returns:
        A BranchProtectionResult with collected details and any errors.
    """
    result = BranchProtectionResult(
        repo_full_name=repo_full_name,
        default_branch="unknown",
    )

    try:
        auth = Auth.Token(github_token)
        gh = Github(auth=auth)

        logger.info("Connecting to GitHub repository: %s", repo_full_name)
        repo: Repository = gh.get_repo(repo_full_name)
        result.default_branch = repo.default_branch

        target_branch_name = branch_name or repo.default_branch
        logger.info("Inspecting branch: %s", target_branch_name)

        branch: Branch = repo.get_branch(target_branch_name)

        if not branch.protected:
            logger.warning(
                "Branch '%s' in '%s' has NO protection rules configured.",
                target_branch_name,
                repo_full_name,
            )
            # Return a fully-populated DTO reflecting the unprotected state.
            result.details = BranchProtectionDetails(
                repo_full_name=repo_full_name,
                branch_name=target_branch_name,
                protection_enabled=False,
                required_pr_reviews=False,
                required_approving_review_count=0,
                dismiss_stale_reviews=False,
                require_code_owner_reviews=False,
                require_status_checks=False,
                enforce_admins=False,
                allow_force_pushes=True,   # unprotected = force-push allowed
                allow_deletions=True,      # unprotected = deletion allowed
            )
        else:
            result.details = _extract_protection_details(repo, branch)

        gh.close()

    except GithubException as exc:
        msg = f"GitHub API error [{exc.status}]: {exc.data.get('message', exc)}"
        logger.error(msg)
        result.collection_errors.append(msg)

    except Exception as exc:  # noqa: BLE001
        msg = f"Unexpected error during GitHub collection: {exc}"
        logger.exception(msg)
        result.collection_errors.append(msg)

    return result
