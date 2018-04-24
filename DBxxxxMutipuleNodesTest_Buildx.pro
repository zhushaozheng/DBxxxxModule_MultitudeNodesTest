#-------------------------------------------------
#
# Project created by QtCreator 2018-04-15T20:11:42
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = DBxxxxMutipuleNodesTest_Buildx
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
	main.cpp \
	mainwindow.cpp \
	common/src/Qt_printf.cpp \
    winpcap/Application/winpcap_application.cpp \
    global.cpp \
    module.cpp

HEADERS += \
	mainwindow.h \
	common/Qt_common_api.h \
    mme/mme_define.h \
    winpcap/Application/winpcap_application.h \
    winpcap/Include/bittypes.h \
    winpcap/Include/ip6_misc.h \
    winpcap/Include/Packet32.h \
    winpcap/Include/pcap.h \
    winpcap/Include/pcap-bpf.h \
    winpcap/Include/pcap-namedb.h \
    winpcap/Include/pcap-stdinc.h \
    winpcap/Include/remote-ext.h \
    winpcap/Include/Win32-Extensions.h \
    winpcap/Include/pcap/bluetooth.h \
    winpcap/Include/pcap/bpf.h \
    winpcap/Include/pcap/namedb.h \
    winpcap/Include/pcap/pcap.h \
    winpcap/Include/pcap/sll.h \
    winpcap/Include/pcap/usb.h \
    winpcap/Include/pcap/vlan.h \
    global.h \
    module.h

FORMS += \
        mainwindow.ui

INCLUDEPATH     +=  ./common \
					./winpcap/Include \
					./winpcap/Application \
					./mme/ \
					./ 
					
LIBS            +=  -L./winpcap/Lib -lPacket     \
                    -L./winpcap/Lib -lwpcap
