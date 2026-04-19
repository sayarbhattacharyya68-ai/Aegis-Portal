import streamlit.web.cli as stcli
import os
import sys

def resolve_path(path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, path)

if __name__ == "__main__":
    # Points to your main.py file
    # We use the absolute path to ensure the executable finds main.py
    main_script = resolve_path("main.py")
    
    sys.argv = [
        "streamlit",
        "run",
        main_script,
        "--global.developmentMode=false",
        "--server.headless=true",
        "--client.toolbarMode=minimal",
    ]
    sys.exit(stcli.main())
