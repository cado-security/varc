# Tested with python 3.10 and PyInstaller 5.4.1

PATHS="../venv/lib/python3.10/site-packages"

python3 -m venv venv
source ./venv/bin/activate
cd cado-host-python


python3 -m pip install --upgrade pip
python3 -m pip install pyinstaller==4.10
python3 -m pip install -r requirements.txt
python3 -m PyInstaller  --onefile --clean --paths $PATHS --target-arch universal2 varc.py
