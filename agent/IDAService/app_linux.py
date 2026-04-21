from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_ROOT = Path(os.environ.get("IDA_OUTPUT_ROOT", str(BASE_DIR / "ida_output")))
LOG_DIR = Path(os.environ.get("IDA_LOG_DIR", str(BASE_DIR / "log")))

PORT = int(os.environ.get("IDA_SERVICE_PORT", "5000"))
MAX_FILE_SIZE = 1024 * 1024 * 1024 * 5
TIMEOUT = int(os.environ.get("IDA_TIMEOUT", "3000"))


LOCAL_IDA_ROOT = Path("/home/wzh/Desktop/tools/IDA")


def _resolve_ida_path(env_name: str, *candidates: str) -> str:
    configured = os.environ.get(env_name)
    if configured:
        return configured

    for candidate in candidates:
        if Path(candidate).exists():
            return candidate

    return candidates[0]


IDA32_PATH = _resolve_ida_path(
    "IDA32_PATH",
    "/opt/ida/ida",
    str(LOCAL_IDA_ROOT / "ida"),
)
IDA64_PATH = _resolve_ida_path(
    "IDA64_PATH",
    "/opt/ida/ida64",
    "/opt/ida/ida",
    str(LOCAL_IDA_ROOT / "ida64"),
    str(LOCAL_IDA_ROOT / "ida"),
)
IDAT32_PATH = _resolve_ida_path(
    "IDAT32_PATH",
    "/opt/ida/idat",
    str(LOCAL_IDA_ROOT / "idat"),
)
IDAT64_PATH = _resolve_ida_path(
    "IDAT64_PATH",
    "/opt/ida/idat64",
    "/opt/ida/idat",
    str(LOCAL_IDA_ROOT / "idat64"),
    str(LOCAL_IDA_ROOT / "idat"),
)

# The Flask service itself may run inside conda, but IDA should use its own
# embedded Python runtime. Do not inject conda PYTHONHOME/PYTHONPATH into IDA.
PYTHON_ENV_KEYS_TO_DROP = (
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONNOUSERSITE",
    "PYTHONUSERBASE",
    "PYTHONEXECUTABLE",
    "PYTHONBREAKPOINT",
    "PYTHONDONTWRITEBYTECODE",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV",
    "CONDA_EXE",
    "CONDA_PROMPT_MODIFIER",
    "CONDA_PYTHON_EXE",
    "_CE_CONDA",
    "_CE_M",
)

BINEXPORT_SCRIPT = BASE_DIR / "export_binexport.py"
EXPORT_SCRIPT = BASE_DIR / "export_hexrays.py"
EXPORT_STRINGS_SCRIPT = BASE_DIR / "export_strings.py"
ANALYZE_SCRIPT = BASE_DIR / "analyze.py"
STRING_XREF_SCRIPT = BASE_DIR / "string_xref_analysis.py"
CALL_GRAPH_SCRIPT = BASE_DIR / "export_call_graph.py"
XREF_SCRIPT = BASE_DIR / "get_function_xrefs.py"


def setup_logger() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"{datetime.now().strftime('%Y%m%d')}-linux.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
    return logging.getLogger(__name__)


logger = setup_logger()
app = Flask(__name__)
app.logger.setLevel(logging.INFO)
OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)


def _path_status(path_value: str) -> dict[str, object]:
    path = Path(path_value)
    return {
        "path": path_value,
        "exists": path.exists(),
        "executable": os.access(path, os.X_OK) if path.exists() else False,
    }


@app.route("/health", methods=["GET"])
def health():
    binaries = {
        "IDA32_PATH": _path_status(IDA32_PATH),
        "IDA64_PATH": _path_status(IDA64_PATH),
        "IDAT32_PATH": _path_status(IDAT32_PATH),
        "IDAT64_PATH": _path_status(IDAT64_PATH),
    }
    missing = [name for name, info in binaries.items() if not info["exists"] or not info["executable"]]
    status_code = 200 if not missing else 503
    return (
        jsonify(
            {
                "status": "ok" if not missing else "error",
                "missing": missing,
                "binaries": binaries,
                "output_root": str(OUTPUT_ROOT),
                "log_dir": str(LOG_DIR),
            }
        ),
        status_code,
    )



def _date_dir() -> Path:
    path = OUTPUT_ROOT / datetime.now().strftime("%Y%m%d")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_filename(name: str) -> str:
    normalized = (name or "").replace("\\", "/")
    base_name = os.path.basename(normalized).strip()
    if not base_name:
        abort(400, "Invalid filename")
    return base_name


def _get_ida_version(form_value: str | None) -> str:
    value = (form_value or "ida").lower()
    return "ida64" if value == "ida64" else "ida"


def _get_ida_binary(ida_version: str, headless: bool = True) -> str:
    if headless:
        return IDAT64_PATH if ida_version == "ida64" else IDAT32_PATH
    return IDA64_PATH if ida_version == "ida64" else IDA32_PATH


def _build_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()

    # Keep the parent shell environment for networking/filesystem behavior,
    # but strip Python/conda variables so IDA initializes its own runtime.
    for key in PYTHON_ENV_KEYS_TO_DROP:
        env.pop(key, None)

    if extra:
        env.update({k: str(v) for k, v in extra.items()})
    return env


def _decode_output(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode(errors="ignore").strip()
    return raw.strip()


def _stage_uploaded_binary(uploaded_file) -> tuple[Path, Path]:
    if not uploaded_file or uploaded_file.filename == "":
        abort(400, "No valid file uploaded")

    analysis_dir = _date_dir()
    filename = _safe_filename(uploaded_file.filename)
    bin_path = analysis_dir / filename
    uploaded_file.save(bin_path)
    logger.info("File staged at %s", bin_path)
    return bin_path, analysis_dir


def _find_binary(binary_name: str) -> Path:
    safe_name = _safe_filename(binary_name)
    today_path = _date_dir() / safe_name
    if today_path.exists():
        return today_path

    candidates = sorted(
        OUTPUT_ROOT.rglob(safe_name),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    abort(404, f"Binary file not found: {safe_name}")


def _find_idb_for_binary(bin_path: Path) -> Path | None:
    for suffix in (".i64", ".idb"):
        candidate = Path(f"{bin_path}{suffix}")
        if candidate.exists():
            return candidate
    return None


def _run_ida(
    ida_path: str,
    script_path: Path,
    target_path: Path,
    *,
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
    timeout: int = TIMEOUT,
    text: bool = False,
) -> subprocess.CompletedProcess:
    ida_binary = Path(ida_path)

    if not ida_binary.exists():
        abort(500, f"IDA executable not found: {ida_path}")
    if not os.access(ida_binary, os.X_OK):
        abort(500, f"IDA executable is not executable: {ida_path}")
    if not script_path.exists():
        abort(500, f"IDA script not found: {script_path}")
    if not target_path.exists():
        abort(404, f"Target file not found: {target_path}")

    ida_log_path = (cwd or target_path.parent) / f"{target_path.name}_{script_path.stem}.ida.log"
    cmd = [ida_path, "-A", "-T", f"-L{ida_log_path}", f"-S{script_path}", str(target_path)]
    logger.info("Running IDA command: %s", " ".join(cmd))

    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd or target_path.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=_build_env(extra_env),
            text=text,
        )
    except subprocess.TimeoutExpired:
        abort(408, "IDA analysis timeout")


def _check_result(result: subprocess.CompletedProcess, action: str) -> None:
    stdout_text = _decode_output(result.stdout)
    stderr_text = _decode_output(result.stderr)
    if stdout_text:
        logger.info("%s stdout: %s", action, stdout_text[:1000])
    if stderr_text:
        logger.info("%s stderr: %s", action, stderr_text[:1000])

    if result.returncode != 0:
        error_msg = stderr_text or stdout_text or f"IDA exited with code {result.returncode}"
        abort(500, f"{action} failed: {error_msg}")


def _choose_existing_file(*candidates: Path) -> Path | None:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _empty_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED):
        pass


def convert_size(size_bytes: int) -> str:
    value = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TB"


@app.route("/reversing_analyze_screenshot", methods=["POST"])
def analyze_with_screenshot_disabled():
    """Linux/headless mode: stage the file and return an empty zip."""
    if request.content_length and request.content_length > MAX_FILE_SIZE:
        abort(413, "File too large")

    uploaded_file = request.files.get("file")
    bin_path, analysis_dir = _stage_uploaded_binary(uploaded_file)

    zip_path = analysis_dir / f"ida_screenshots_{bin_path.name}.zip"
    _empty_zip(zip_path)
    logger.info("Screenshot endpoint is disabled in Linux mode; returned empty zip for %s", bin_path.name)

    return send_file(
        zip_path,
        as_attachment=True,
        download_name=zip_path.name,
        mimetype="application/zip",
    )


@app.route("/export_binexport", methods=["POST"])
def export_binexport():
    try:
        binary_name = request.form.get("binary_name")
        if not binary_name:
            abort(400, "No binary name provided")

        ida_version = _get_ida_version(request.form.get("ida_version"))
        idat_path = _get_ida_binary(ida_version, headless=True)
        bin_path = _find_binary(binary_name)

        result = _run_ida(idat_path, BINEXPORT_SCRIPT, bin_path, cwd=bin_path.parent)
        _check_result(result, "BinExport export")

        export_path = bin_path.parent / f"{bin_path.name}.BinExport"
        if not export_path.exists():
            abort(500, f"BinExport file not generated: {export_path}")

        zip_path = bin_path.parent / f"ida_analysis_{bin_path.name}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(export_path, export_path.name)

        return send_file(
            zip_path,
            as_attachment=True,
            download_name=zip_path.name,
            mimetype="application/zip",
        )
    except Exception as exc:
        logger.error("Error during BinExport export: %s", exc, exc_info=True)
        raise


@app.route("/export_pseudo_c", methods=["POST"])
def export_pseudo_c():
    try:
        binary_name = request.form.get("binary_name")
        if not binary_name:
            abort(400, "No binary name provided")

        ida_version = _get_ida_version(request.form.get("ida_version"))
        idat_path = _get_ida_binary(ida_version, headless=True)
        bin_path = _find_binary(binary_name)
        source_output_dir = bin_path.parent / "source"
        source_output_dir.mkdir(parents=True, exist_ok=True)

        result = _run_ida(idat_path, EXPORT_SCRIPT, bin_path, cwd=bin_path.parent)
        _check_result(result, "Pseudo C export")

        output_path = _choose_existing_file(
            bin_path.parent / f"{bin_path.name}_pseudo.c",
            bin_path.parent / f"{bin_path.stem}_pseudo.c",
        )
        if output_path is None:
            abort(500, f"Pseudo C file not generated for {bin_path.name}")

        pseudo_path = source_output_dir / output_path.name
        if pseudo_path.exists():
            pseudo_path.unlink()
        shutil.move(str(output_path), str(pseudo_path))

        logger.info(
            "%s exported pseudo C successfully, binary size: %s",
            bin_path.name,
            convert_size(bin_path.stat().st_size),
        )

        return send_file(
            pseudo_path,
            as_attachment=True,
            download_name=pseudo_path.name,
            mimetype="text/plain",
        )
    except Exception as exc:
        logger.error("Error during pseudo C export: %s", exc, exc_info=True)
        raise


@app.route("/get_function_call_info", methods=["POST"])
def get_function_call_info():
    try:
        binary_name = request.form.get("binary_name")
        function_name = request.form.get("function_name")
        if not binary_name or not function_name:
            abort(400, "Missing required parameters: binary_name or function_name")

        ida_version = _get_ida_version(request.form.get("ida_version"))
        idat_path = _get_ida_binary(ida_version, headless=True)
        bin_path = _find_binary(binary_name)

        result = _run_ida(
            idat_path,
            ANALYZE_SCRIPT,
            bin_path,
            cwd=bin_path.parent,
            extra_env={"IDA_FUNC_NAME": function_name},
        )
        _check_result(result, "Function call info export")

        json_files = sorted(
            [
                path
                for path in bin_path.parent.glob("*.json")
                if path.name.startswith(("ida_slice_", "ida_combined_analysis_"))
                and function_name in path.name
            ],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not json_files:
            abort(500, "Analysis result file not found")

        with open(json_files[0], "r", encoding="utf-8") as handle:
            return jsonify(json.load(handle)), 200
    except Exception as exc:
        logger.error("Error during function call info export: %s", exc, exc_info=True)
        raise


@app.route("/export_strings", methods=["POST"])
def export_strings():
    try:
        if request.content_length and request.content_length > MAX_FILE_SIZE:
            abort(413, "File too large")

        uploaded_file = request.files.get("file")
        bin_path, _ = _stage_uploaded_binary(uploaded_file)

        ida_version = _get_ida_version(request.form.get("ida_version"))
        idat_path = _get_ida_binary(ida_version, headless=True)

        result = _run_ida(idat_path, EXPORT_STRINGS_SCRIPT, bin_path, cwd=bin_path.parent)
        _check_result(result, "String export")

        output_path = bin_path.parent / f"{bin_path.name}_strings.json"
        if not output_path.exists():
            abort(500, "String export file not generated")

        with open(output_path, "r", encoding="utf-8") as handle:
            return jsonify(json.load(handle))
    except Exception as exc:
        logger.error("Error during string export: %s", exc, exc_info=True)
        raise


@app.route("/string_context", methods=["POST"])
def string_context():
    try:
        if request.is_json:
            data = request.get_json() or {}
            binary_path = data.get("binary_path", "")
            binary_name = data.get("binary_name", "")
            strings = data.get("strings", [])
            max_xrefs = data.get("max_xrefs", 10)
        else:
            binary_path = request.form.get("binary_path", "")
            binary_name = request.form.get("binary_name", "")
            strings = json.loads(request.form.get("strings", "[]"))
            max_xrefs = int(request.form.get("max_xrefs", 10))

        if not binary_name and binary_path:
            binary_name = os.path.basename(binary_path.replace("\\", "/"))
        if not binary_name:
            abort(400, "Missing binary_path or binary_name parameter")
        if not strings:
            abort(400, "Missing strings parameter")

        bin_path = _find_binary(binary_name)
        idb_path = _find_idb_for_binary(bin_path)
        if not idb_path:
            abort(400, f"No IDB file found for {bin_path.name}. Please analyze the binary first with /export_strings.")

        ida_version = "ida64" if idb_path.suffix == ".i64" else "ida"
        idat_path = _get_ida_binary(ida_version, headless=True)

        input_path = idb_path.parent / f"{idb_path.name}_xref_input.json"
        output_path = idb_path.parent / f"{idb_path.name}_xref_output.json"
        with open(input_path, "w", encoding="utf-8") as handle:
            json.dump({"strings": strings, "max_xrefs": max_xrefs}, handle, ensure_ascii=False)

        try:
            result = _run_ida(
                idat_path,
                STRING_XREF_SCRIPT,
                bin_path,
                cwd=idb_path.parent,
                extra_env={
                    "IDA_INPUT_FILE": str(input_path),
                    "IDA_OUTPUT_FILE": str(output_path),
                },
                text=True,
            )
            stdout_text = _decode_output(result.stdout)
            stderr_text = _decode_output(result.stderr)
            if stdout_text:
                logger.info("string_context stdout: %s", stdout_text[:1000])
            if stderr_text:
                logger.info("string_context stderr: %s", stderr_text[:1000])

            if result.returncode != 0 and not output_path.exists():
                abort(500, f"IDA analysis failed: {stderr_text or stdout_text}")

            if not output_path.exists():
                abort(500, "IDA did not produce output file")

            with open(output_path, "r", encoding="utf-8") as handle:
                context_results = json.load(handle)

            return jsonify(
                {
                    "status": "success",
                    "binary_path": binary_path,
                    "idb_path": str(idb_path),
                    "results": context_results,
                }
            )
        finally:
            for temp_path in (input_path, output_path):
                try:
                    if temp_path.exists():
                        temp_path.unlink()
                except OSError:
                    logger.warning("Failed to clean temp file: %s", temp_path)
    except json.JSONDecodeError as exc:
        abort(400, f"Invalid JSON in strings parameter: {exc}")
    except Exception as exc:
        logger.error("Error during string context export: %s", exc, exc_info=True)
        raise


@app.route("/export_call_graph", methods=["POST"])
def export_call_graph():
    try:
        binary_name = request.form.get("binary_name")
        if not binary_name:
            abort(400, "Missing binary_name parameter")

        ida_version = _get_ida_version(request.form.get("ida_version"))
        idat_path = _get_ida_binary(ida_version, headless=True)
        bin_path = _find_binary(binary_name)

        result = _run_ida(idat_path, CALL_GRAPH_SCRIPT, bin_path, cwd=bin_path.parent)
        _check_result(result, "Call graph export")

        output_path = bin_path.parent / f"{bin_path.name}_call_graph.json"
        if not output_path.exists():
            abort(500, "Call graph output file not generated")

        with open(output_path, "r", encoding="utf-8") as handle:
            return jsonify(json.load(handle))
    except Exception as exc:
        logger.error("Error during call graph export: %s", exc, exc_info=True)
        raise


@app.route("/get_function_xrefs", methods=["POST"])
def get_function_xrefs():
    try:
        binary_name = request.form.get("binary_name")
        function_name = request.form.get("function_name")
        xref_type = request.form.get("xref_type", "caller")
        depth = request.form.get("depth", "1")

        if not binary_name or not function_name:
            abort(400, "Missing binary_name or function_name parameter")

        ida_version = _get_ida_version(request.form.get("ida_version"))
        idat_path = _get_ida_binary(ida_version, headless=True)
        bin_path = _find_binary(binary_name)

        result = _run_ida(
            idat_path,
            XREF_SCRIPT,
            bin_path,
            cwd=bin_path.parent,
            extra_env={
                "XREF_FUNCTION_NAME": function_name,
                "XREF_TYPE": xref_type,
                "XREF_DEPTH": str(depth),
            },
        )
        _check_result(result, "Function xref export")

        output_path = bin_path.parent / f"{bin_path.name}_{function_name}_xrefs.json"
        if not output_path.exists():
            abort(500, "Xref output file not generated")

        with open(output_path, "r", encoding="utf-8") as handle:
            return jsonify(json.load(handle))
    except Exception as exc:
        logger.error("Error during xref export: %s", exc, exc_info=True)
        raise


if __name__ == "__main__":
    try:
        from waitress import serve

        serve(
            app,
            host="0.0.0.0",
            port=PORT,
            max_request_body_size=10 * 1024 * 1024 * 1024,
        )
    except ImportError:
        app.run(host="0.0.0.0", port=PORT)
