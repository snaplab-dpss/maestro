FROM --platform=linux/amd64 ubuntu:18.04

# https://stackoverflow.com/questions/51023312/docker-having-issues-installing-apt-utils
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update --fix-missing
RUN apt-get -y install build-essential make sudo wget curl git

RUN useradd -m user
RUN echo "user:user" | chpasswd
RUN adduser user sudo

# Ensure sudo group users are not 
# asked for a password when using 
# sudo command by ammending sudoers file
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER user

RUN git clone https://github.com/fchamicapereira/maestro.git /home/user/maestro

WORKDIR /home/user/maestro

RUN chmod +x ./setup.sh
RUN ./setup.sh

CMD [ "/bin/bash" ]