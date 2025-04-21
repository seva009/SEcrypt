# SEcrypt
## Todos
- [x] Make sure it works on windows
- [ ] Add the port option
- [ ] Bundle the templates in the executable
- [ ] Add more encryption methods to the web ui
- [x] Steganography

## Установка
- Вы можете скачать готовый файл с GitHub: [SEcrypt](https://github.com/seva009/SEcrypt/releases/tag/v0.1). Также для его запуска потребуется [vsr](https://aka.ms/vs/17/release/vc_redist.x64.exe)
- После скачивания перетащите файл в командную строку и в конце добавьте -s. Пример: "C:\Users\User\Downloads\Telegram Desktop\SEcrypt.exe" -s
- У вас должна появится надпись: SEcrypt by Empers0n_ (главное после этого не закрывайте командную строку)
- Следующим шагом переходите в браузер и в строку поиска пишите: localhost:23444
- На этом все, далее можете свободно взаимодействовать с программой.

## Связь:
- [GitHub](https://github.com/seva009)
- [Mail](mailto:empers0n@kabanyara.ru)

## Сборка:
### Linux
```bash 
sudo apt update
sudo apt upgrade
sudo apt install g++ make cmake
git clone https://github.com/seva009/SEcrypt.git
cd SEcrypt
mkdir build
cd build
cmake ..
make
```

### Windows
Установите [MSYS2](https://www.msys2.org/) и выполните следующие команды:
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
> Если вы будете изменять web UI то изменяйте index.html а потом конвертируйте его в header.h с помощью HTML_builder и пересоберите проект
> Все скрипты и стили для web UI должны быть в файле index.html

## Баги:
    - Стеганограмма в аудиофайлах не сохраняет изначальную длину сообщения
    -
