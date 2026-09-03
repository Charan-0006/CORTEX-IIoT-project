from pathlib import Path
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def load_config(config_path=None):
    """Load system configuration from YAML file."""
    if config_path is None:
        config_path = PROJECT_ROOT / "config.yaml"
    
    if Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}
