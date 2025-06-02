#!/usr/bin/env sh
set -e


sudo apt update && sudo apt upgrade -y

# wireguard
sudo apt -y install wireguard
# linphone
sudo apt -y install linphone

