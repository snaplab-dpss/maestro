FROM --platform=linux/amd64 ubuntu:focal

# https://stackoverflow.com/questions/51023312/docker-having-issues-installing-apt-utils
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Lisbon

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

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

ENV MAESTRO_DIR=/home/user/maestro

# Setting default python version
RUN sudo update-alternatives --install /usr/bin/python python /usr/bin/python3.8 1
RUN sudo apt-get -y install vim lshw kmod iproute2 net-tools linux-generic linux-headers-generic
RUN pip3 install numpy scapy

# Pre generate all parallel implementations
COPY generate-nf.sh /home/user/
RUN /home/user/generate-nf.sh nop
RUN /home/user/generate-nf.sh sbridge
RUN /home/user/generate-nf.sh bridge
RUN /home/user/generate-nf.sh pol
RUN /home/user/generate-nf.sh fw
RUN /home/user/generate-nf.sh nat
RUN /home/user/generate-nf.sh lb
RUN /home/user/generate-nf.sh psd
RUN /home/user/generate-nf.sh cl

COPY --chown=user:user bind-igb-uio.sh /home/user/
COPY --chown=user:user allocate-hugepages.sh /home/user/
COPY --chown=user:user check-tsx.sh /home/user/
COPY --chown=user:user entrypoint.sh /home/user/

RUN chmod +x /home/user/bind-igb-uio.sh
RUN chmod +x /home/user/allocate-hugepages.sh
RUN chmod +x /home/user/check-tsx.sh
RUN chmod +x /home/user/entrypoint.sh

SHELL [ "/bin/bash", "-c" ]
ENTRYPOINT [ "/home/user/entrypoint.sh" ]
CMD [ "/bin/bash" ]