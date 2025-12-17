Изменение компилятора CLion:

Нажмите Ctrl + Alt + S (Settings).

Перейдите в Build, Execution, Deployment -> Toolchains.

Нажмите кнопку + и выберите Visual Studio.

Дождитесь, пока CLion определит пути (у вас должен быть установлен Visual Studio или Build Tools).

Важно: Перетащите "Visual Studio" в самый верх списка, чтобы сделать его основным.

Нажмите OK и пересоберите проект (Build -> Rebuild Project).

Настройка CLion:

Edit Configurations

program arguments - Конфигурация запуска основного файла программы:
input.mylang ast.mmd cfg assembler-code

Working directory - рабочая директория (корень проекта):
C:/Users/DN3672/CLionProjects/system-software-lab-3

Скомпилировать главный файл в объектный файл windows можно через команду:
nasm -f win64 -g program.asm -o program.obj

Для линковки и получения исполняемого файла можно использовать:
gcc program.obj -o program.exe

Проверить, сохранились ли секции с данными для отладки
objdump -h program.exe

Запустить программу можно через
.\program.exe

Посмотреть результат можно через:
echo $LASTEXITCODE


Я пишу дебаггер
Пишу его для винды, можешь использовать функции винды для этого
мне нужно из .exe файла получить метки исходного кода,
.debug_info,
.debug_line,
.debug_info
мне сейчас нужно мочь благодаря этим меткам выполнять код
по меткам - по шагам
и смотреть значения переменным благодаря debug_info









