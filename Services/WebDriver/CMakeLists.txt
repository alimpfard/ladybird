set(SOURCES
    BiDi/BrowsingContextModule.cpp
    BiDi/Commands.cpp
    BiDi/PermissionsModule.cpp
    BiDi/ScriptModule.cpp
    BiDi/SessionModule.cpp
    BiDiConnection.cpp
    BrowserConnection.cpp
    Client.cpp
    Session.cpp
    WebSocketConnection.cpp
    main.cpp
)

add_executable(WebDriver ${SOURCES})

target_include_directories(WebDriver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../..)
target_include_directories(WebDriver PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/../..)
target_include_directories(WebDriver PRIVATE ${LADYBIRD_SOURCE_DIR})
target_include_directories(WebDriver PRIVATE ${LADYBIRD_SOURCE_DIR}/Services)

target_link_libraries(WebDriver PRIVATE LibCore LibFileSystem LibGfx LibIPC LibMain LibURL LibWebCommon)
target_link_libraries(WebDriver PRIVATE OpenSSL::Crypto OpenSSL::SSL)

if (WIN32)
    ladybird_windows_bin(WebDriver)
endif()
