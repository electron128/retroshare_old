TEMPLATE = lib
CONFIG += staticlib
CONFIG -= qt
TARGET = miniupnpc
DESTDIR = lib

# unmodified miniupnpc-1.3 fails
# ..\..\all-qmake-build\miniupnp\miniupnpc-1.3\minissdpc.c:50: error: invalid application of 'sizeof' to incomplete type 'struct sockaddr_un'

# miniupnpc-1.9
# rename miniupnpcstrings.h.in and add the desired content
# works!
MINIUPNP_DIR = miniupnpc-1.9

# required to avoid creation of weird functions names beginning with _impl__
DEFINES *= STATICLIB

win32{
    # allow call to getnameinfo in ws2_32
    # proper define lead to special function names
    # see this page for details:
    # http://mingw.5.n7.nabble.com/Undefined-reference-to-getaddrinfo-td5694.html
    # this does not work
    #DEFINES *= "WINVER=WindowsXP"
    # this works
    DEFINES *= "_WIN32_WINNT=0x0501"
}

HEADERS +=\
        $${MINIUPNP_DIR}/portlistingparse.h \
        $${MINIUPNP_DIR}/receivedata.h      \
        $${MINIUPNP_DIR}/connecthostport.h  \
        $${MINIUPNP_DIR}/igd_desc_parse.h   \
        $${MINIUPNP_DIR}/miniupnpc.h        \
        $${MINIUPNP_DIR}/minixml.h          \
        $${MINIUPNP_DIR}/minisoap.h         \
        $${MINIUPNP_DIR}/miniwget.h         \
        $${MINIUPNP_DIR}/upnpc.h            \
        $${MINIUPNP_DIR}/upnpcommands.h     \
        $${MINIUPNP_DIR}/upnpreplyparse.h   \
        $${MINIUPNP_DIR}/testminixml.h      \
        $${MINIUPNP_DIR}/minixmlvalid.h     \
        $${MINIUPNP_DIR}/testupnpreplyparse.h\
        $${MINIUPNP_DIR}/minissdpc.h        \
        $${MINIUPNP_DIR}/upnperrors.h       \
        $${MINIUPNP_DIR}/testigddescparse.h

SOURCES +=\
        $${MINIUPNP_DIR}/portlistingparse.c \
        $${MINIUPNP_DIR}/receivedata.c      \
        $${MINIUPNP_DIR}/connecthostport.c  \
        $${MINIUPNP_DIR}/igd_desc_parse.c   \
        $${MINIUPNP_DIR}/miniupnpc.c        \
        $${MINIUPNP_DIR}/minixml.c          \
        $${MINIUPNP_DIR}/minisoap.c         \
        $${MINIUPNP_DIR}/miniwget.c         \
        $${MINIUPNP_DIR}/upnpc.c            \
        $${MINIUPNP_DIR}/upnpcommands.c     \
        $${MINIUPNP_DIR}/upnpreplyparse.c   \
        $${MINIUPNP_DIR}/testminixml.c      \
        $${MINIUPNP_DIR}/minixmlvalid.c     \
        $${MINIUPNP_DIR}/testupnpreplyparse.c\
        $${MINIUPNP_DIR}/minissdpc.c        \
        $${MINIUPNP_DIR}/upnperrors.c       \
        $${MINIUPNP_DIR}/testigddescparse.c
