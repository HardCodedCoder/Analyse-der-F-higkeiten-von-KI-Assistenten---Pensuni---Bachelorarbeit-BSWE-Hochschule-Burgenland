import os
import glob

# Define the root directory
root_dir = "doc"

# Define the file extensions to delete
file_extensions = ["*.aux", "*.log", "*.out", "*.toc", "*.bbl", "*.blg", "*.bcf", "*.run.xml", "*.fdb_latexmk", "*.fls", "*.synctex.gz"]

# Iterate over all subdirectories and files
for ext in file_extensions:
    for file in glob.glob(os.path.join(root_dir, '**', ext), recursive=True):
        try:
            os.remove(file)
            print(f"Deleted: {file}")
        except OSError as e:
            print(f"Error deleting {file}: {e}")

print("Cleanup complete.")