QT += core network testlib
CONFIG += console c++14 testcase
CONFIG -= app_bundle

INCLUDEPATH += ../src .

SOURCES += \
    CryptoTest.cpp \
    TestDecryptor.cpp \
    ../src/crypto/CryptoEngine.cpp \
    ../src/crypto/FF1Cipher.cpp

HEADERS += \
    TestDecryptor.h \
    ../src/crypto/CryptoEngine.h \
    ../src/crypto/FF1Cipher.h

unix: LIBS += -largon2 -lsodium -lcrypto
win32: LIBS += -largon2 -lsodium -llibcrypto
