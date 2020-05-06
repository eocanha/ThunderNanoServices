
find_package(ocdm REQUIRED)
set(GST_CENC_PLUGIN_IMPLEMENTATION gstdashdecrypt_ocdm)

add_library(${GST_CENC_PLUGIN_IMPLEMENTATION} STATIC "")

target_include_directories(${GST_CENC_PLUGIN_IMPLEMENTATION}
    PUBLIC
        ${GST_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_sources(${GST_CENC_PLUGIN_IMPLEMENTATION} 
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Decryptor.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/Exchanger.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ResponseCallback.cpp)

target_link_libraries(${GST_CENC_PLUGIN_IMPLEMENTATION}
        PUBLIC
            ocdm::ocdm
            ${OCDM_LIBRARIES})