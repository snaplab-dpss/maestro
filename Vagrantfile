# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  # config.vm.box = "ubuntu/lunar64"
  config.vm.box = "ubuntu/jammy64"
  # config.vm.box = "ubuntu/focal64"
  
  config.ssh.forward_agent = true
  config.vm.synced_folder "../maestro", "/home/vagrant/maestro"
  
  config.vm.provider :virtualbox do |vb|
    vb.name = "maestro"
    vb.memory = 4096
    vb.cpus = 4
  end

  config.vm.provision "shell", privileged: false, inline: <<-SCRIPT
    sudo apt update && sudo apt upgrade -y
    cd /home/vagrant/maestro
    git submodule update --init --recursive
    ./build.sh
    echo "source /home/vagrant/maestro/paths.sh" >> /home/vagrant/.bashrc
  SCRIPT

end