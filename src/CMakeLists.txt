
cmake_minimum_required(VERSION 3.1)
project(dns-c-ares)

if(APPLE)
    # no warning
    # https://stackoverflow.com/questions/31561309/cmake-warnings-under-os-x-macosx-rpath-is-not-specified-for-the-following-targe
    set(CMAKE_MACOSX_RPATH 0)
endif()


set(bin_name dns)

set(Source_files 
	${CMAKE_CURRENT_LIST_DIR}/main.c
	${CMAKE_CURRENT_LIST_DIR}/dns.h
	${CMAKE_CURRENT_LIST_DIR}/dns.c
	)


add_executable(${bin_name} ${Source_files})

# include other directories
target_include_directories(${bin_name} PRIVATE ${CMAKE_CURRENT_LIST_DIR})

## defines options link-libraries
#target_compile_definitions(${self_binary_name} PRIVATE "_USE_DATA2")
if (WIN32)
  # visual studio file encoding
  target_compile_options(${bin_name} PRIVATE /source-charset:utf-8 /execution-charset:utf-8)
  
  # disable ZERO_CHECK project
  set(CMAKE_SUPPRESS_REGENERATION true)

#elseif(APPLE)
else()
  # fPIC for other library link
  target_compile_options(${bin_name} PRIVATE -fPIC)
  target_compile_options(${bin_name} PRIVATE -fvisibility=hidden)
  target_compile_options(${bin_name} PRIVATE -fno-common )
  target_link_libraries(${bin_name} dl) # dlopen  
endif()



# c-ares options
set(CARES_STATIC ON CACHE "" BOOL FORCE)
set(CARES_SHARED OFF CACHE "" BOOL FORCE)
set(CARES_INSTALL OFF CACHE "" BOOL FORCE)
set(CARES_BUILD_TESTS OFF CACHE "" BOOL FORCE)
set(CARES_BUILD_TOOLS OFF CACHE "" BOOL FORCE)

# link other libraries
set(cares_home ${CMAKE_CURRENT_LIST_DIR}/../lib/c-ares-1.15.0)
target_include_directories(${bin_name} PRIVATE ${cares_home})
if (NOT TARGET c-ares)
    add_subdirectory(${cares_home}  build_libcares)
endif ()
target_link_libraries(${bin_name} c-ares)

# visual studio project tree
source_group(files FILES ${Source_files})

if (WIN32)
    # support Linux Console Application
    # failed
    #set_target_properties(
    #${bin_name}
    #PROPERTIES
    #    VS_GLOBAL_KEYWORD "Linux"
    #    VS_GLOBAL_ApplicationType "Linux"
    #    VS_GLOBAL_ApplicationTypeRevision "1.0"
    #    VS_GLOBAL_TargetLinuxPlatform "Generic"
    #    VS_GLOBAL_LinuxProjectType "{D51BCBC9-82E9-4017-911E-C93873C4EA2B}"
    #    # not work
    #    #VS_GLOBAL_PlatformToolset "Remote_GCC_1_0"
    #    
    #)
    #set_target_properties(
    #c-ares
    #PROPERTIES
    #    VS_GLOBAL_KEYWORD "Linux"
    #    VS_GLOBAL_ApplicationType "Linux"
    #    VS_GLOBAL_ApplicationTypeRevision "1.0"
    #    VS_GLOBAL_TargetLinuxPlatform "Generic"
    #    VS_GLOBAL_LinuxProjectType "{D51BCBC9-82E9-4017-911E-C93873C4EA2B}"
    #)
endif()