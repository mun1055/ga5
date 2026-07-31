# LXD via snap (WSL2 Ubuntu works)
sudo snap install lxd && sudo lxd init --auto

# unprivileged container with a hard memory cap, 1 CPU, no host mounts
lxc launch ubuntu:22.04 sandbox
lxc config set sandbox limits.memory 512MB
lxc config set sandbox limits.memory.enforce hard
lxc config set sandbox limits.cpu 1

# kill its networking so the net probe fails
lxc config device add sandbox eth0 none

# copy the script in and run it, capturing stdout+stderr together
lxc file push probe.sh sandbox/root/probe.sh
lxc exec sandbox -- bash -lc 'bash /root/probe.sh 2>&1'
