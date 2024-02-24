#!/bin/sh

# Windows
mkdir win;
cd win;
curl -L https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 -o winPEAS.ps1;
curl -L https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1 -o PowerUp.ps1;
curl -L https://github.com/int0x33/nc.exe/raw/master/nc.exe -o nc32.exe;
curl -L https://github.com/int0x33/nc.exe/raw/master/nc64.exe -o nc64.exe;
curl -L https://github.com/djhohnstein/SharpWeb/releases/download/v1.2/SharpWeb.exe -o SharpWeb.exe;
curl -L https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip -o JuicyPotatoNG.zip; unzip JuicyPotatoNG.zip; rm JuicyPotatoNG.zip;

## Windows  AD
curl -L https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe -o Certify.exe;
curl -L https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe -o Rubeus.exe;
curl -L https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -o PowerView.ps1;
curl -L https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1 -o Powermad.ps1;

cd ..;
