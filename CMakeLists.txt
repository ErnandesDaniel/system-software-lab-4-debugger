cmake_minimum_required(VERSION 4.0)
project(system_software_lab_4_debugger C)

set(CMAKE_C_STANDARD 17)

add_executable(system_software_lab_4_debugger main.c)

# Указываем путь к заголовочным файлам Capstone
# Это позволит использовать #include <capstone/capstone.h>
include_directories(lib/capstone/include)

# Подключаем библиотеки
# Добавляем dbghelp и полный путь к capstone.lib
target_link_libraries(system_software_lab_4_debugger
        PRIVATE
        dbghelp
        "${CMAKE_CURRENT_SOURCE_DIR}/lib/capstone/lib/capstone.lib"
)

# 4. Автоматизация: копируем capstone.dll в папку с .exe файлом после сборки.
# Без этого файла программа выдаст ошибку "библиотека не найдена" при запуске.
add_custom_command(TARGET system_software_lab_4_debugger POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/lib/capstone/bin/capstone.dll"
        $<TARGET_FILE_DIR:system_software_lab_4_debugger>
)