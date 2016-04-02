apt-get updatecurl -sSL https://get.docker.com/ | sh
apt-get install python-pip daemontools daemontools-run
pip install -U butterfly
start svscan
cd /home/ubuntu/docker
docker build -t angr .
