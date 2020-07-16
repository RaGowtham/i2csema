## Getting Started

Follow below instructions to build and install the SEMA utility on target machine.

### Prerequisites

Install build-essential package to install all tools used along with make. Install git, hexer and i2c-tools.

```
sudo apt install build-essential git hexer i2c-tools
```

### Build and Install

Download the source code from ADLINK git repository

```
git clone http://GitLab.Adlinktech.com/AATI_CCoE/SEMA_4.0_Linux_SandBox.git
```

Change directory to SEMA_4.0_Linux_SandBox and run make.

```
cd SEMA_4.0_Linux_SandBox
sudo make
```

To install driver modules, dynamic library and utilities  into root file system.

```
sudo make install
```


