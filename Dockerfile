FROM --platform=linux/amd64 ubuntu:jammy

# https://stackoverflow.com/questions/51023312/docker-having-issues-installing-apt-utils
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Lisbon

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# The install scripts require sudo (no need to clean apt cache, the setup script will install stuff)
RUN apt-get update && apt-get install -y sudo

# Create a user with passwordless sudo
RUN adduser --disabled-password --gecos '' docker
RUN adduser docker sudo
RUN echo '%docker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER docker
WORKDIR /home/docker/

# Configure ssh directory
RUN mkdir /home/docker/.ssh
RUN chown -R docker:docker /home/docker/.ssh

# Install some nice to have applications
RUN sudo apt-get update --fix-missing
RUN sudo apt-get -y install \
    man \
    build-essential \
    wget \
    git \
    vim \
    tzdata \
    tmux \
    iputils-ping \
    iproute2 \
    net-tools \
    tcpreplay \
    iperf \
    psmisc \
    htop \
    gdb \
    xdot \
    xdg-utils \
    libcanberra-gtk-module \
    libcanberra-gtk3-module \
    python3-pip

RUN sudo dpkg-reconfigure --frontend noninteractive tzdata

# Setting up for tmux
RUN echo "set -g default-terminal \"screen-256color\"" >> /home/docker/.tmux.conf
RUN echo "set-option -g default-shell /bin/bash" >> /home/docker/.tmux.conf

# Source the profile on open
RUN echo "source ~/.profile" >> /home/docker/.bashrc

###########################
#  Building dependencies  #
###########################

COPY --chown=docker:docker . maestro
WORKDIR /home/docker/maestro

RUN ./setup.sh

###########################
#     Additional tools    #
###########################

# If you want to install additional packages or augment the container in any other way,
# do it here so that you don't have to rebuild everything from scratch.

# Run bash on open
SHELL ["/bin/bash", "-c"]
CMD [ "/bin/bash" ]