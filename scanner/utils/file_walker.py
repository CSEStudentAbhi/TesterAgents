import os

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".json", ".env", ".html", ".css"
}

# Folders to always skip
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next",
    "__pycache__", ".cache", "coverage", ".nyc_output", "vendor"
}

def walk_files(root_dir):
    """
    Walk project directory recursively and yield (absolute_path, relative_path)
    for all scannable files, skipping irrelevant directories.
    """
    files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Remove skipped dirs in-place so os.walk won't descend into them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SCANNABLE_EXTENSIONS or filename in (".env", ".env.local", ".env.production"):
                abs_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(abs_path, root_dir)
                files.append((abs_path, rel_path.replace("\\", "/")))

    return files
