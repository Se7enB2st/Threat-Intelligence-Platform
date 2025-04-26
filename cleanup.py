import os
import shutil

# List of files and directories to remove
to_remove = [
    "threat_analyzer/models",
    "models",
    "Dockerfile.analyzer",
    "Dockerfile.ml",
    "Dockerfile.web",
    "Dockerfile.db",
    "automation.py",
    "domain_analyzer.py",
    "reset_database.py",
    "threat_aggregation.py",
    "ip_analyzer.py",
    "download_packages.sh",
    "download_packages.py",
    "packages",
    "model_cache",
    "threat_cache",
    "data_manager.py",
    "ml_detector.py",
    "threat_service.py",
    "threat_visualizer.py",
    "cli.py",
    "create_tables.py",
    "__pycache__",
    "threat_analyzer/__pycache__",
    "threat_intelligence.db",
    "threat_automation.log"
]

for item in to_remove:
    try:
        if os.path.isfile(item):
            os.remove(item)
            print(f"Removed file: {item}")
        elif os.path.isdir(item):
            shutil.rmtree(item)
            print(f"Removed directory: {item}")
    except Exception as e:
        print(f"Could not remove {item}: {e}") 