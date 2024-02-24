#!/bin/sh

# Linux
mkdir linux;
cd linux;
# From github - https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh;
curl -L https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32 -o pspy32;
curl -L https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -o pspy64;

# AD
pip3 install certipy-ad

cd ../;
