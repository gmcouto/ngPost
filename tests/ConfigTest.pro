QT -= gui
QT += testlib
CONFIG += console testcase
include(../src/ngPost.pri)
TARGET = ConfigTest
DEFINES += NGPOST_TESTING_HOOKS
SOURCES -= main.cpp
for(source, SOURCES): CONFIG_TEST_SOURCES += $$PWD/../src/$$source
for(header, HEADERS): CONFIG_TEST_HEADERS += $$PWD/../src/$$header
SOURCES = $$CONFIG_TEST_SOURCES $$PWD/ConfigTest.cpp
HEADERS = $$CONFIG_TEST_HEADERS
RESOURCES = $$PWD/../src/resources/resources.qrc
