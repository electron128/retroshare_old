
# remeber top dir, to not move out of it
TOP_DIR=$PWD

# exit on error
set -e

cd $TOP_DIR/miniupnp
wget http://miniupnp.free.fr/files/download.php?file=miniupnpc-1.9.tar.gz -O miniupnpc-1.9.tar.gz
tar xvf miniupnpc-1.9.tar.gz
# TODO: fill strings with correct values
# or handle this in the qmake project file?
mv miniupnpc-1.9/miniupnpcstrings.h.in miniupnpc-1.9/miniupnpcstrings.h
patch miniupnpc-1.9/miniwget.c < min.patch

cd $TOP_DIR/bzip2
wget http://www.bzip.org/1.0.6/bzip2-1.0.6.tar.gz
tar xvf bzip2-1.0.6.tar.gz

cd $TOP_DIR/openssl
wget http://www.openssl.org/source/openssl-1.0.1g.tar.gz
# trouble with symlinks
# cygwin: does not work
# 7zip: does not work
# mingw works!!!
tar xvf openssl-1.0.1g.tar.gz

cd $TOP_DIR/zlib
wget http://zlib.net/zlib-1.2.8.tar.gz
tar xvf zlib-1.2.8.tar.gz

##wget https://red.libssh.org/attachments/download/52/libssh-0.6.0rc1.tar.gz
# with cygwin the path to the ca-certs has to be set
#wget --ca-directory=/usr/ssl/certs https://red.libssh.org/attachments/download/52/libssh-0.6.0rc1.tar.gz
#tar xvf libssh-0.6.0rc1.tar.gz

#wget http://protobuf.googlecode.com/files/protobuf-2.4.1.tar.gz
#tar xvf protobuf-2.4.1.tar.gz

echo "-----------------------------------------------------------------------"
echo "If nothing went wrong, sources of supportlibs should now be at the correct places"
echo "If you are on Windows: run this script with MingW Shell"
echo "You need to have wget installed, in MingW Shell run"
echo "ming-get install msys-wget"
echo "Cygwin will not work, because it has troubles with symlinks in openssl.tar"
echo "WARNING: this script does not check shasums, TODO: add shasum check"
echo "-----------------------------------------------------------------------"


