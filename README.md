# SEcrypt
## Todos
- [x] Make sure it works on windows
- [x] Add the port option
- [x] Bundle the templates in the executable
- [ ] Add more encryption methods to the web ui
- [x] Steganography

## Run:

### Windows
- Download the finished file from GitHub: [SEcrypt](https://github.com/seva009/SEcrypt/releases/latest). 
- After downloading, drag the file to the command line and add flag "-s". Example: .\SEcrypt.exe -s
- Open [127.0.0.1:23444](http://127.0.0.1:23444) in your web browser

### Linux
- Download the executable from [GitHub releases](https://github.com/seva009/SEcrypt/releases/latest)
- Open the terminal (e.g. by pressing Ctrl+Alt+T) in the same directory as the executable and run `./SEcrypt -s`. More information about command line arguments can be found by running `./SEcrypt -h`
- Open [127.0.0.1:23444](http://127.0.0.1:23444) in your web browser

## Connect:
- [GitHub](https://github.com/seva009)
- [Mail](mailto:empers0n@kabanyara.ru)

## Build:
### Linux

#### Install required tools

##### Ubuntu/Debian
```bash 
sudo apt update
sudo apt upgrade
sudo apt install g++ make cmake
```

##### Arch (the preferred one)
```bash
# Optionally run a full system upgrade:
sudo pacman -Syu

# Install required packages
sudo pacman -S g++ make cmake
```

#### Build the project

```bash 
git clone https://github.com/seva009/SEcrypt.git
cd SEcrypt
cmake -B build
cd build
make
```

### Windows
Install [MSYS2](https://www.msys2.org/) and run the following commands:
```bash
pacman -Syu
pacman -Su
pacman -S mingw-w64-x86_64-toolchain
pacman -S mingw-w64-x86_64-cmake
pacman -S git
git clone https://github.com/seva009/SEcrypt.git
cd SEcrypt
mkdir build
cd build
cmake ..
make
```

> [!IMPORTANT]
> If you are going to change the web UI, then change index.html and then convert it to header.h using HTML_builder and rebuild the project
> All scripts and styles for web UI should be in the file index.html

## Bugs:
    Steganography in audio files does not preserve the original form of the message.
