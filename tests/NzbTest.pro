QT += core network testlib
CONFIG += console c++14 testcase
CONFIG -= app_bundle

INCLUDEPATH += ../src

SOURCES += \
    NzbTest.cpp

HEADERS += \
    ../src/EncryptionSettings.h \
    ../src/utils/CmdOrGuiApp.h
