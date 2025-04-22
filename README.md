# SEcrypt
## Todos
- [x] Make sure it works on windows
- [ ] Add the port option
- [ ] Bundle the templates in the executable
- [ ] Add more encryption methods to the web ui
- [x] Steganography

## Installation:

### Windows
- Download the finished file from GitHub: [SEcrypt](https://github.com/seva009/SEcrypt/releases/tag/v0.1). Also, to run it you will need [vsr](https://aka.ms/vs/17/release/vc_redist.x64.exe)
- After downloading, drag the file to the command line and add at the end "-s". Пример: "C:\Users\User\Downloads\Telegram Desktop\SEcrypt.exe" -s
- You will see a message: SEcrypt by Empers0n_ (the main thing after this is to not close the command line)
- The next step is to go to your browser and type it into the text search: [localhost:23444](localhost:23444)
- That's all, now you can freely interact with the program

### Linux
- Download the executable from [GitHub releases](https://github.com/seva009/SEcrypt/releases/tag/v0.1)
- Open the terminal (e.g. by pressing Ctrl+Alt+T) in the same directory as the executable and run `./SEcrypt -s`. More information about command line arguments can be found by running `./SEcrypt -h`
- Open [localhost:23444](localhost:23444) in your web browser

## Connect:
- [GitHub](https://github.com/seva009)
- [Mail](mailto:empers0n@kabanyara.ru)

## Сборка:
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
