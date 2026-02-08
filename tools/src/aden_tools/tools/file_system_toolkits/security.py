import errno
import os

# Use user home directory for workspaces
WORKSPACES_DIR = os.path.expanduser("~/.hive/workdir/workspaces")


def get_secure_path(path: str, workspace_id: str, agent_id: str, session_id: str) -> str:
    """Resolve and verify a path within a 3-layer sandbox (workspace/agent/session).

    Security: Validates both lexical (abspath) and physical (realpath) paths to prevent
    symlink escape attacks. Rejects symlinks pointing outside the sandbox.
    """
    if not workspace_id or not agent_id or not session_id:
        raise ValueError("workspace_id, agent_id, and session_id are all required")

    # Ensure session directory exists: runtime/workspace_id/agent_id/session_id
    session_dir = os.path.join(WORKSPACES_DIR, workspace_id, agent_id, session_id)
    os.makedirs(session_dir, exist_ok=True)

    # Resolve absolute path (lexical - does not follow symlinks)
    if os.path.isabs(path):
        # Treat absolute paths as relative to the session root if they start with /
        rel_path = path.lstrip(os.sep)
        lexical_path = os.path.abspath(os.path.join(session_dir, rel_path))
    else:
        lexical_path = os.path.abspath(os.path.join(session_dir, path))

    # Verify lexical path is within session_dir
    common_prefix = os.path.commonpath([lexical_path, session_dir])
    if common_prefix != session_dir:
        raise ValueError(f"Access denied: Path '{path}' is outside the session sandbox.")

    # Security: Validate realpath to prevent symlink escape attacks
    try:
        # Resolve both paths to real locations (follows symlinks, normalizes case)
        real_session_dir = os.path.normcase(os.path.realpath(session_dir))
        real_path = os.path.normcase(os.path.realpath(lexical_path))

        # Verify resolved path stays within sandbox
        try:
            real_common = os.path.commonpath([real_path, real_session_dir])
        except ValueError:
            # Different drives on Windows or path incompatibility
            raise ValueError(
                f"Access denied: Path '{path}' is outside the session sandbox."
            ) from None

        if real_common != real_session_dir:
            raise ValueError(
                f"Access denied: Path '{path}' resolves via symlink outside the session sandbox."
            )
    except OSError as e:
        # Handle circular symlinks; allow other OS errors to propagate
        if e.errno == errno.ELOOP:
            raise ValueError(f"Access denied: Circular symlink detected at '{path}'")
        raise

    return lexical_path
