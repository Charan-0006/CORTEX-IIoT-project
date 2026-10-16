from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def get_project_root() -> Path:
    """Return absolute path to the project root directory."""
    return PROJECT_ROOT

def ensure_directory(path: Path) -> Path:
    """Ensure that a directory path exists."""
    path.mkdir(parents=True, exist_ok=True)
    return path
