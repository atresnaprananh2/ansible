#!/usr/bin/env bash

tar xzf /home/oracle/pyinstall/Python-3.10.8.tgz -C /home/oracle/pyinstall
cd /home/oracle/pyinstall/Python-3.10.8 
sudo ./configure --with-system-ffi --with-computed-gotos --enable-loadable-sqlite-extensions --with-openssl=/home/oracle/openssl
sudo make -j
# to remove the unused stuff: find . -maxdepth 1  -mtime +1 -exec rm -rf {} \;
# to install pip we can use: python -m ensurepip --upgrade
# it will install pip into $HOME/.local/bin
sudo make altinstall 
sudo rm /home/oracle/pyinstall/Python-3.10.8.tgz
sudo update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.10 1
sudo update-alternatives --set python3 /usr/local/bin/python3.10

tar xzf /home/oracle/pyinstall/cx_Oracle-7.3.0.tar.gz -C /home/oracle/pyinstall