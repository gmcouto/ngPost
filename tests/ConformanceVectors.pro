# Conformance test suite over the vendored yEnc encryption standards v1.2
# test vector fixtures (tests/test-vectors/). Standalone qmake project so the
# test builds without touching the ngPost GUI/CLI targets.
TEMPLATE = app
QT += core network testlib
QT -= gui
CONFIG += cmdline console
CONFIG -= app_bundle
TARGET = ConformanceVectors
SOURCES += ConformanceVectors.cpp
# Bake the vendored fixture location into the binary (qmake $$PWD = this .pro
# directory), so the test reads fixtures inside the ngPost source tree from
# any build directory.
DEFINES += TEST_VECTORS_DIR=\\\"$$PWD/test-vectors\\\"
