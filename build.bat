pyinstaller -y --clean -F --name p22p.exe --hidden-import zope.interface --hidden-import _cffi_backend --key WhyD01EvenEncryptThisFile? --console p22p/__main__.py
pyinstaller -y --clean -F --name p22p_gui.exe --hidden-import zope.interface --hidden-import _cffi_backend --key WhyD01EvenEncryptThisFile --windowed p22p/client_gui.py
