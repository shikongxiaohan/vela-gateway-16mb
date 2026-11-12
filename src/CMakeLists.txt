# This file was automatically generated for projects
# without default 'CMakeLists.txt' file.
#
# 只列 *.cpp，*.h 由编译器按组件 include 路径找
# （idf_component_register 会把本目录加进 include path，
#  所以 main.cpp 里 #include "vela_version.h" 一定能找到同目录下的那个文件）。
#
# 这里不能用 CONFIGURE_DEPENDS。IDF 在 component_get_requirements 阶段会以
# "script mode" 重复 include 这个文件，而 CONFIGURE_DEPENDS 在 script/find_package
# 模式下是非法的，CMake 会报 "CONFIGURE_DEPENDS is invalid for script and find
# package modes"，整个构建在 configure 阶段就挂了。
#
# vela_version.h 由 tools/version_util.py 从根目录 version.txt 生成，
# 内容是固件版本号（主.次.构建.修订，修订号最多四位，前导零不补）。
# 它是头文件，改了会被依赖扫描自动重编，不用手动 clean。

file(GLOB_RECURSE app_sources ${CMAKE_SOURCE_DIR}/src/*.cpp)

idf_component_register(SRCS ${app_sources})
