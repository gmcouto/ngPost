QT += core testlib
CONFIG += console c++14 testcase
CONFIG -= app_bundle

INCLUDEPATH += ../src

SOURCES += \
    CryptoTest.cpp \
    ../src/crypto/CryptoEngine.cpp \
    ../src/crypto/FF1Cipher.cpp

HEADERS += \
    ../src/crypto/CryptoEngine.h \
    ../src/crypto/FF1Cipher.h

unix: LIBS += -largon2 -lsodium -lcrypto
win32: LIBS += -largon2 -lsodium -llibcrypto
