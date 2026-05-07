import zipfile
import os
import tempfile
import shutil

def extract_zip(uploaded_file):
    """Extract uploaded ZIP and return path to extracted directory."""
    tmp_dir = tempfile.mkdtemp(prefix="codescan_")
    zip_path = os.path.join(tmp_dir, "project.zip")

    with open(zip_path, "wb") as f:
        f.write(uploaded_file.read())

    extract_dir = os.path.join(tmp_dir, "project")
    os.makedirs(extract_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_dir)

    return extract_dir, tmp_dir

def cleanup(tmp_dir):
    """Remove temporary extraction directory."""
    try:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass
