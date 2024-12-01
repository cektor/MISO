# MISO
ISO MD5 | SHA-256 Verifier CheckSum Tool. Graphical User Interface and Cross Platform Operational

<h1 align="center">MISO Logo</h1>

<p align="center">
  <img src="misolo.png" alt="MISO Logo" width="150" height="150">
</p>


----------------------

# Linux Screenshot
![Linux(pardus)](screenshot/miso_linux.png)  

# Windows Screenshot
![Windows(11)](screenshot/miso_windows.png) 

--------------------
Install Git Clone and Python3

Github Package Must Be Installed On Your Device.

git
```bash
sudo apt install git -y
```

Python3
```bash
sudo apt install python3 -y 

```

pip
```bash
sudo apt install python3-pip

```

# Required Libraries

PyQt5
```bash
pip install PyQt5
```
PyQt5-sip
```bash
pip install PyQt5 PyQt5-sip
```

PyQt5-tools
```bash
pip install PyQt5-tools
```

Required Libraries for Debian/Ubuntu
```bash
sudo apt-get install python3-pyqt5
sudo apt-get install qttools5-dev-tools
```

----------------------------------


# Installation
Install MISO

```bash
sudo git clone https://github.com/cektor/MISO.git
```
```bash
cd MISO
```

```bash
python3 miso.py

```

# To compile

NOTE: For Compilation Process pyinstaller must be installed. To Install If Not Installed.

pip install pyinstaller 

Linux Terminal 
```bash
pytohn3 -m pyinstaller --onefile --windowed miso.py
```

Windows VSCode Terminal 
```bash
pyinstaller --onefile --noconsole miso.py
```

MacOS VSCode Terminal 
```bash
pyinstaller --onefile --noconsole miso.py
```

# To install directly on Windows or Linux


Linux (based debian) Terminal: Linux (debian based distributions) To install directly from Terminal.
```bash
wget -O Setup_Linux64.deb https://github.com/cektor/MISO/releases/download/1.00/Setup_Linux64.deb && sudo apt install ./Setup_Linux64.deb && sudo apt-get install -f -y
```

Windows Installer CMD (PowerShell): To Install from Windows CMD with Direct Connection.
```bash
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/cektor/MISO/releases/download/1.00/Setup_Win64.exe' -OutFile 'Setup_Win64.exe'" && start /wait Setup_Win64.exe
```

Release Page: https://github.com/cektor/MISO/releases/tag/1.00

----------------------------------
