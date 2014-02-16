#ifndef MMI_H
#define MMI_H

#include <string>

#include <retroshare/rsiface.h>

/*

  mmi: machine-machine-interface

  provides functions to
  - list accounts (pgpid, sslid, name, location)
  - create new identity/location
  - import pgp-key
  - export pgp-key
  - create ssh-passwordhash
  - create ssh-key

  more ideas:
  - create qrcode
  - print own certificate

  all functions take a string as input if input is required
  all functions save their result in a string

  this is useful for scripting, webinterfaces and the Android port

  libqrencode: cerate qrcode
  http://fukuchi.org/works/qrencode/
  miniz: create png images
  http://code.google.com/p/miniz/

  libssh has no function to save a key to a file
  https://red.libssh.org/issues/77
*/

// argc and argv are passed to libretroshare,
// this enables the usage of --basedir option
// set skipInit to true if you already have called RsInit::InitRetroshare()

int mmiListAccounts(std::string& output,
                    int argc, char** argv, bool skipInit = false);

int mmiListPrivatePGPCertificates(std::string& output,
                                  int argc, char** argv, bool skipInit = false);

int mmiGeneratePGPCertificate(const std::string& input, std::string& output,
                              int argc, char** argv, bool skipInit = false);

int mmiGenerateSSLCertificate(const std::string& input, std::string& output,
                              int argc, char** argv, bool skipInit = false);

int mmiGeneratePGPandSSLCertificate(const std::string& input, std::string& output,
                                    int argc, char** argv, bool skipInit = false);

int mmiImportPGPKey(const std::string& input, std::string& output,
                    int argc, char** argv, bool skipInit = false);

int mmiExportPGPKey(const std::string& input, std::string& output,
                    int argc, char** argv, bool skipInit = false);

int mmiGenerateSSHPasswordhash(const std::string& input, std::string& output);

int mmiGenerateSSHKey(const std::string& input, std::string& output);


// a wrapper around mmi functions, to provide access from stdin and stdout
int executeMMICommand(const std::string& command, int argc, char **argv);



// --- private things below ---

// param skipInit: if set to true, this functions does nothing and returns 0
// returns result from RsInit()
int mmiTryRsInit(bool skipInit, int argc, char** argv, std::string& output);

class mmiNotify: public NotifyClient
{
public:
    virtual bool askForPassword(const std::string &, bool, std::string &pw)
    {
        //std::cerr<<"mmiNotify mPasswd=\""<<mPasswd<<"\""<<std::endl;
        pw=mPasswd;
        return true;
    }
    std::string mPasswd;
};

#endif // MMI_H
