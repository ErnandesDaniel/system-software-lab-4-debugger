

Настройка CLion:

Edit Configurations

program arguments - Конфигурация запуска основного файла программы:
input.mylang ast.mmd cfg assembler-code

Working directory - рабочая директория (корень проекта):
C:/Users/DN3672/CLionProjects/system-software-lab-3

Скомпилировать главный файл в объектный файл windows можно через команду:
nasm -f win64 main.asm -o main.obj

Для линковки и получения исполняемого файла можно использовать:
gcc main.obj -o main.exe

Запустить программу можно через
.\main.exe

Посмотреть результат можно через:
echo $LASTEXITCODE