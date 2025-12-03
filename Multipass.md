# Building a Lintap-ready Ubuntu
These instructions cover building an Ubuntu VM on your local system that is usable for either the dotnet or sysdig based implementations.

The basic premise is to use your local disk for and system as much as possible, and the Ubuntu instance to run the sensor and collect data.

## Pre-requisites
* Install and run [Multipass](https://canonical.com/multipass) with a default image.
* Clone repos for Wintap and Lintap
```sh
cd ~/git
git clone  https://github.com/LLNL/Lintap.git
git clone  https://github.com/LLNL/Wintap.git
```
* Build the Lintap VM
```sh
cd ~/git/Lintap
cp multipass-config.env.example multipass-config.env
# Edit and set mounts appropriate for your system
./multipass-lintap.sh
```

Much whirring will occur as the VM is brought up and configured. Something could go wrong... check the cloud-init YAML that is embedded in the script to help debug.

Once complete, you can connect with:

```sh
# Connect using multipass as the Ubuntu user. Uses the generated ssh-key and should always work.
multipass shell lintap-dev
# Connect with ssh, which uses your ~/.ssh/id_ed25519 key and connects as root. This is also what VS Code will use.
ssh lintap-dev
```



