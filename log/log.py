import logging
from pathlib import Path

from config import config_manager

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DEFAULT_LOG_FILE_PATH = config_manager.config["Log"]["file_path"]


def _resolve_log_path(log_file_path: str) -> str:
    path = Path(log_file_path).expanduser()
    if not path.is_absolute():
        project_root = Path(__file__).resolve().parent.parent
        path = project_root / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path.resolve())


def _same_file_handler(handler: logging.Handler, log_file_path: str) -> bool:
    if not isinstance(handler, logging.FileHandler):
        return False
    try:
        return Path(handler.baseFilename).resolve() == Path(log_file_path).resolve()
    except Exception:
        return False


def set_log_file(log_file_path: str, replace_existing_file_handlers: bool = True) -> str:
    resolved_log_path = _resolve_log_path(log_file_path)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    if replace_existing_file_handlers:
        for handler in list(root_logger.handlers):
            if isinstance(handler, logging.FileHandler):
                root_logger.removeHandler(handler)
                handler.close()

    if not any(_same_file_handler(handler, resolved_log_path) for handler in root_logger.handlers):
        file_handler = logging.FileHandler(
            resolved_log_path,
            encoding="utf-8",
            errors="ignore",
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root_logger.addHandler(file_handler)

    return resolved_log_path


set_log_file(DEFAULT_LOG_FILE_PATH, replace_existing_file_handlers=False)

logger = logging.getLogger(name="VulnAgentLogger")
