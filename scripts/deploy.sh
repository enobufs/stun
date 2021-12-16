#!bin/bash
set -e 
cd ..

tar -zcvf stun.tar.gz .

scp stun.tar.gz ubuntu@ec2-54-88-131-100.compute-1.amazonaws.com:/home/ubuntu
ssh ubuntu@ec2-54-88-131-100.compute-1.amazonaws.com tar -xvzf stun.tar.gz

ssh ubuntu@ec2-54-88-131-100.compute-1.amazonaws.com npm install -g node-stun

ssh ubuntu@ec2-54-88-131-100.compute-1.amazonaws.com node-stun-server

