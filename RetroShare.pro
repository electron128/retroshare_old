TEMPLATE = subdirs

# to allow build of complete project at once, with using the -j parameter of make
# this forces to build each project in the order listed here
CONFIG += ordered

SUBDIRS += \
        supportlibs/supportlibs.pro     \ # comment this if you have compiled the libs, to make qtcreator faster
        openpgpsdk/src/openpgpsdk.pro \
        #supportlibs/pegmarkdown/pegmarkdown.pro \
        libbitdht/src/libbitdht.pro \
        libretroshare/src/libretroshare.pro \
        retroshare-gui/src/retroshare-gui.pro \
        #retroshare-nogui/src/retroshare-nogui.pro \
        #plugins/plugins.pro
