#include "mmi.h"

#include <retroshare/rsinit.h>
#include <util/rsdir.h>
#include <util/rsrandom.h>
#include "ssh/rssshd.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <iostream>
#include <sstream>

int mmiListAccounts(std::string &output, int argc,
                    char **argv, bool skipInit /*= false*/)
{
    if(mmiTryRsInit(skipInit, argc, argv, output) != 0)
    {
        return -1;
    }

    std::list<std::string> accountIds;
    RsInit::getAccountIds(accountIds);

    std::list<std::string>::iterator it;
    for(it = accountIds.begin(); it != accountIds.end(); it++)
    {
        std::string gpgId, gpgName, gpgEmail, sslName;
        if(RsInit::getAccountDetails(*it, gpgId, gpgName, gpgEmail, sslName))
        {
            // don't add gpgEmail, because it is not used anymore
            output += *it + "\t" + sslName + "\t" + gpgId + "\t" + gpgName + "\n";
        }
    }
    return 0;
}
int mmiListPrivatePGPCertificates(std::string& output,
                                  int argc, char** argv, bool skipInit /*= false*/)
{
    if(mmiTryRsInit(skipInit, argc, argv, output) != 0)
    {
        return -1;
    }

    std::list<std::string> pgpIds;
    RsInit::GetPGPLogins(pgpIds);

    std::list<std::string>::iterator it;
    for(it = pgpIds.begin(); it != pgpIds.end(); it++)
    {
        std::string pgpName, email;
        if(RsInit::GetPGPLoginDetails(*it, pgpName, email))
        {
            output += *it + "\t" + pgpName +"\n";
        }
    }
    return 0;
}

int mmiGeneratePGPCertificate(const std::string& input, std::string& output,
                              int argc, char** argv, bool skipInit /*= false*/)
{
    if(mmiTryRsInit(skipInit, argc, argv, output) != 0)
    {
        return -1;
    }

    std::string name, email, passwd, pgpId, errString;

    std::stringstream ss(input);
    std::getline(ss,name,'\t');
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiGeneratePGPCertificate(): could not get name (wrong usage?)\n";
        return -1;
    }
    std::getline(ss,passwd);
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiGeneratePGPCertificate(): could not get passwd (wrong usage?)\n";
        return -1;
    }

    if (RsInit::GeneratePGPCertificate(name, email, passwd, pgpId, errString) == false)
    {
        std::cerr << "Error in mmiGeneratePGPCertificate(): RsInit::GeneratePGPCertificate() returned false"
                  << std::endl;
        std::cerr << "errString = " << errString << std::endl;
        output = errString + "\n";
        return -1;
    }
    output = pgpId + "\n";
    return 0;
}
int mmiGenerateSSLCertificate(const std::string& input, std::string& output,
                              int argc, char** argv, bool skipInit /*= false*/)
{
    if(mmiTryRsInit(skipInit, argc, argv, output) != 0)
    {
        return -1;
    }

    std::string PGPId, PGPPasswd, genLoc;

    std::stringstream ss(input);
    std::getline(ss, PGPId, '\t');
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiGenerateSSLCertificate(): could not get pgpId (wrong usage?)\n";
        return -1;
    }
    std::getline(ss, PGPPasswd, '\t');
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiGenerateSSLCertificate(): could not get pgpPassword (wrong usage?)\n";
        return -1;
    }
    std::getline(ss, genLoc);
    if(ss.fail() || ss.bad())
    {
        output= "Error in mmiGenerateSSLCertificate(): could not get locationName (wrong usage?)\n";
        return -1;
    }

    // create callback for askForPassword Notify event
    // Password is required to sign SSL certificate
    mmiNotify notify;
    notify.mPasswd=PGPPasswd;
    RsControl::earlyInitNotificationSystem();
    rsNotify->registerNotifyClient(&notify);

    // bool     RsInit::GenerateSSLCertificate(
    // const std::string& gpg_id, const std::string& org,
    // const std::string& loc, const std::string& country,
    // const std::string& passwd, std::string &sslId,
    // std::string &errString
    // )

    //generate a random ssl password
    std::string sslPasswd = RSRandom::random_alphaNumericString(RsInit::getSslPwdLen()) ;

    RsInit::SelectGPGAccount(PGPId);

    std::string sslId, errString;
    if(RsInit::GenerateSSLCertificate(PGPId, "", genLoc, "", sslPasswd, sslId, errString))
    {
        RsInit::LoadPassword(sslId, sslPasswd);
        if(RsInit::SavePassword() == false)
        {
            std::cerr << "Error in mmiGenerateSSLCertificate(): RsInit::SavePassword() returned false"
                      << std::endl;
            // RsInit::SavePassword() prints detailed errors to stderr
            output = "Error: could not save SSL password on disk. See stderr for details\n";
            return -1;
        }
    }
    else
    {
        std::cerr << "Error in mmiGenerateSSLCertificate(): RsInit::GenerateSSLCertificate() returned false"
                  << std::endl;

        // the returned errString is currently useless
        // errString for wrong passwort: "No Error"
        //output = "Error: could not generate a SSL certificate. Reason: " + errString + "\n";
        // we don't know what happened, because the functions in the lower layers don't tell us
        output = "Failed to Generate your new Certificate, maybe PGP id or PGP password is wrong!\n";
        return -1;
    }
    output = sslId + "\n";
    return 0;
}
int mmiGeneratePGPandSSLCertificate(const std::string& input, std::string& output,
                                    int argc, char** argv, bool skipInit /*= false*/)
{
    if(mmiTryRsInit(skipInit, argc, argv, output) != 0)
    {
        return -1;
    }
    std::string name, password, locationName;// input
    std::string pgpId, sslId;// output

    std::stringstream ss(input);
    std::getline(ss, name, '\t');
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiGeneratePGPandSSLCertificate(): could not get name (wrong usage?)\n";
        return -1;
    }
    std::getline(ss, password, '\t');
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiGeneratePGPandSSLCertificate(): could not get password (wrong usage?)\n";
        return -1;
    }
    std::getline(ss, locationName);
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiGeneratePGPandSSLCertificate(): could not get locationName (wrong usage?)\n";
        return -1;
    }

    std::string pgpOutput;
    int pgpOk = mmiGeneratePGPCertificate(name+"\t"+password+"\n", pgpOutput, 0, 0, true);
    if(pgpOk != 0)
    {
        output = pgpOutput;
        return -1;
    }

    std::stringstream sspgp(pgpOutput);
    std::getline(sspgp, pgpId);
    if(sspgp.fail() || sspgp.bad())
    {
        output = "Error in mmiGeneratePGPandSSLCertificate(): error parsing output of mmiGeneratePGPCertificate. Please report this Problem.\n";
        return -1;
    }

    std::string sslOutput;
    int sslOk = mmiGenerateSSLCertificate(pgpId+"\t"+password+"\t"+locationName+"\n", sslOutput, 0, 0, true);
    if(sslOk != 0){
        output = sslOutput;
        return -1;
    }

    std::stringstream ssssl(sslOutput);
    std::getline(ssssl, sslId);
    if(ssssl.fail() || ssssl.bad())
    {
        output = "Error in mmiGeneratePGPandSSLCertificate(): error parsing output of mmiGenerateSSLCertificate. Please report this Problem.\n";
        return -1;
    }
    output = pgpId + "\t" + sslId + "\n";
    return 0;
}
int mmiImportPGPKey(const std::string& input, std::string& output,
                    int argc, char** argv, bool skipInit /*= false*/)
{
    if(mmiTryRsInit(skipInit, argc, argv, output) != 0)
    {
        return -1;
    }

    std::string path;

    std::stringstream ss(input);
    std::getline(ss, path);
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiImportPGPKey(): could not get path (wrong usage?)\n";
        return -1;
    }

    std::string PGPId, errString;
    if(RsInit::importIdentity(path,PGPId,errString))
    {
        output = PGPId + "\n";
        return 0;
    }
    else
    {
        std::cerr << "Error in mmiImportPGPKey(): RsInit::importIdentity() returned false" << std::endl;
        output = "Error: could not Import identity. Reason: " + errString + "\n";
        return -1;
    }
}
int mmiExportPGPKey(const std::string& input, std::string& output,
                    int argc, char** argv, bool skipInit /*= false*/)
{
    if(mmiTryRsInit(skipInit, argc, argv, output) != 0)
    {
        return -1;
    }

    std::string PGPId, path;

    std::stringstream ss(input);
    std::getline(ss, PGPId, '\t');
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiExportPGPKey(): could not get pgpId (wrong usage?)\n";
        return -1;
    }
    std::getline(ss, path);
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiExportPGPKey(): could not get path (wrong usage?)\n";
        return -1;
    }

    if(RsInit::exportIdentity(path, PGPId))
    {
        return 0;
    }
    else
    {
        std::cerr << "Error in mmiExportPGPKey(): RsInit::exportIdentity() returned false" << std::endl;
        output = "Error: could not export identity " + PGPId + " to file " + path +
                 " make sure, that the path is accessible. See stderr for details.\n";
        return -1;
    }
}

int mmiGenerateSSHPasswordhash(const std::string& input, std::string& output)
{
    std::string saltBin;
    std::string pwdHashRadix64;
    std::string sshPwdForHash = "";

    std::stringstream ss(input);
    std::getline(ss, sshPwdForHash);
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiGenerateSSHPasswordhash(): could not get password (wrong usage?)\n";
        return -1;
    }

    if(sshPwdForHash.length() < 8)
    {
        output = "SSH Password must be at least 8 characters long.\n";
        return -1;
    }

    GenerateSalt(saltBin);
    if (!GeneratePasswordHash(saltBin, sshPwdForHash, pwdHashRadix64))
    {
        std::cerr << "Error Generating Password Hash, password probably too short";
        std::cerr << pwdHashRadix64;
        std::cerr << std::endl;
        output = "Error Generating Password Hash, password probably too short.\n";
        return -1;
    }

    /* checking match */
    if (CheckPasswordHash(pwdHashRadix64, sshPwdForHash))
    {
        output = pwdHashRadix64 + '\n';
        return 0;
    }
    else
    {
        std::cerr << "ERROR: Failed CheckPassword!";
        std::cerr << std::endl;
        output = "ERROR: Failed CheckPassword!\n";
        return -1;
    }
}

int mmiGenerateSSHKey(const std::string& input, std::string& output)
{
    std::string pathToKeyfile;

    std::stringstream ss(input);
    std::getline(ss, pathToKeyfile);
    if(ss.fail() || ss.bad())
    {
        output = "Error in mmiGenerateSSHKey(): could not get pathToKeyfile (wrong usage?)\n";
        return -1;
    }

    // container classes, which free their RSA/BN on destruction
    // this way, the compiler decides when to free the memory
    // useful, because we have too many exit points
    class RSA_destructor{
    public:
        RSA_destructor(RSA* rsa){mRSA=rsa;}
        ~RSA_destructor(){if(mRSA!=NULL){RSA_free(mRSA);}}
        RSA* mRSA;
    };
    class BIGNUM_destructor{
    public:
        BIGNUM_destructor(BIGNUM* bn){mBN=bn;}
        ~BIGNUM_destructor(){if(mBN!=NULL){BN_free(mBN);}}
        BIGNUM* mBN;
    };

    // don't know if licrypto needs any sort of init
    // does libcrypto need a random seed?
    // authssl does this:
    //    // actions_to_seed_PRNG();
    //    RAND_seed(passwd, strlen(passwd));
    // "OpenSSL will attempt to seed the random number generator automatically upon instantiation"
    // http://wiki.openssl.org/index.php/Random_Numbers

    // i used the code from http://www.openssh.org/ to learn how to make keys
    int bits = 2048;
    RSA* privateRSAKey = RSA_new();
    BIGNUM* f4 = BN_new();

    // when these objs get destroyed, they free the structs
    RSA_destructor rsa_destructor(privateRSAKey);
    BIGNUM_destructor bignum_destructor(f4);

    if(privateRSAKey == NULL){
        std::cerr << "Error in "<< __func__ << "(): privateRSAKey == NULL" << std::endl;
        output = "Error in " + std::string(__func__) + "(): privateRSAKey == NULL\n";
        return -1;
    }
    if(f4 == NULL){
        std::cerr << "Error in "<< __func__ << "(): f4 == NULL" << std::endl;
        output = "Error in " + std::string(__func__) + "(): f4 == NULL\n";
        return -1;
    }
    if(! BN_set_word(f4, RSA_F4)){
        std::cerr << "Error in "<< __func__ << "(): set f4 failed" << std::endl;
        output = "Error in " + std::string(__func__) + "(): set f4 failed\n";
        return -1;
    }
    if(! RSA_generate_key_ex(privateRSAKey, bits, f4, NULL)){
        std::cerr << "Error in "<< __func__ << "(): RSA_generate_key_ex() failed" << std::endl;
        output = "Error in " + std::string(__func__) + "(): RSA_generate_key_ex() failed\n";
        return -1;
    }

    FILE* outFile = NULL;
    if (NULL == (outFile = RsDirUtil::rs_fopen(pathToKeyfile.c_str(), "w")))
    {
        output = "Error: could not open file " + pathToKeyfile + "\n";
        return -1;
    }
    /*
     int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc,
                                            unsigned char *kstr, int klen,
                                            pem_password_cb *cb, void *u);
    */
    if(!PEM_write_RSAPrivateKey(outFile, privateRSAKey, NULL,
                                     NULL, 0,
                                     NULL, NULL))
    {
        output = "Error: could not write SSH key to file " + pathToKeyfile + "\n";
        fclose(outFile);
        return -1;
    }
    fclose(outFile);

    // todo: return fingerprint

    return 0;
}

int executeMMICommand(const std::string& command, int argc, char** argv)
{
    if(command == "help")
    {
        std::cerr <<
        "mmi: machine-machine interface\n"
        "This is a simple Interface to modify Keys and Locations.\n"
        "usage: retroshare-nogui --mmi <command>\n"
        "\n"
        "Input:  a single line is read from stdin if the command requires input data\n"
        "        separate input values with '\\t' and end the line with '\\n'\n"
        "Output: error: one or more lines with a human readable text"
        "        ok   : zero or more lines with values separated by '\\t'\n"
        "All strings are UTF-8 encoded.\n"
        "The return value is 0 on success\n"
        "\n"
        "command: list-accounts\n"
        "input  : -\n"
        "output : sslId sslName pgpId pgpName\n"
        "\n"
        "command: list-pgp-private-keys\n"
        "input  : -\n"
        "output : pgpId pgpName\n"
        "\n"
        "command: generate-pgp-certificate\n"
        "input  : pgpName pgpPassword\n"
        "output : pgpId\n"
        "\n"
        "command: generate-ssl-certificate\n"
        "input  : pgpId pgpPassword locationName\n"
        "output : sslId\n"
        "\n"
        "command: generate-pgp-and-ssl-certificate\n"
        "input  : pgpName pgpPassword locationName\n"
        "output : pgpId sslId\n"
        "\n"
        "command: import-pgp-key\n"
        "input  : pathToKeyfile\n"
        "output : pgpId\n"
        "\n"
        "command: export-pgp-key\n"
        "input  : pgpId pathToKeyfile\n"
        "output : -\n"
        "\n"
        "command: generate-ssh-passwordhash\n"
        "input  : sshPassword\n"
        "output : sshPasswordHash\n"
        "\n"
        "command: generate-ssh-key\n"
        "input  : pathToKeyfile\n"
        "output : -\n"
        << std::endl;

        return 0;
    }
    else if (command == "list-accounts")
    {
        std::string output;
        int returnValue = mmiListAccounts(output, argc, argv);
        std::cout << output;
        return returnValue;
    }
    else if (command == "list-pgp-private-keys")
    {
        std::string output;
        int returnValue = mmiListPrivatePGPCertificates(output, argc, argv);
        std::cout << output;
        return returnValue;
    }
    else if (command == "generate-pgp-certificate")
    {
        std::string input, output;
        std::getline(std::cin,input);
        input += '\n';
        int returnValue = mmiGeneratePGPCertificate(input, output, argc, argv);
        std::cout << output;
        return returnValue;
    }
    else if (command == "generate-ssl-certificate")
    {
        std::string input, output;
        std::getline(std::cin,input);
        input += '\n';
        int returnValue = mmiGenerateSSLCertificate(input, output, argc, argv);
        std::cout << output;
        return returnValue;
    }
    else if (command == "generate-pgp-and-ssl-certificate")
    {
        std::string input, output;
        std::getline(std::cin,input);
        input += '\n';
        int returnValue = mmiGeneratePGPandSSLCertificate(input, output, argc ,argv);
        std::cout << output;
        return returnValue;
    }
    else if (command == "import-pgp-key")
    {
        std::string input, output;
        std::getline(std::cin,input);
        input += '\n';
        int returnValue = mmiImportPGPKey(input, output, argc, argv);
        std::cout << output;
        return returnValue;
    }
    else if (command == "export-pgp-key")
    {
        std::string input, output;
        std::getline(std::cin,input);
        input += '\n';
        int returnValue = mmiExportPGPKey(input, output, argc, argv);
        std::cout << output;
        return returnValue;
    }
    else if (command == "generate-ssh-passwordhash")
    {
        std::string input, output;
        std::getline(std::cin,input);
        input += '\n';
        int returnValue = mmiGenerateSSHPasswordhash(input, output);
        std::cout << output;
        return returnValue;
    }
    else if (command == "generate-ssh-key")
    {
        std::string input, output;
        std::getline(std::cin,input);
        input += '\n';
        int returnValue = mmiGenerateSSHKey(input, output);
        std::cout << output;
        return returnValue;
    }
    else
    {
        std::cerr << "Error in executeMMICommand(): command \""
                  << command << "\" not implemented. See \"--mmi help\" for a list of commands." << std::endl;
        return -1;
    }
}

int mmiTryRsInit(bool skipInit, int argc, char** argv, std::string& output)
{
    if(skipInit == false)
    {
        RsInit::InitRsConfig();
        int initResult = RsInit::InitRetroShare(argc, argv);
        if(initResult < 0)
        {
            std::stringstream ss;
            ss << initResult;
            output = "could not init Retroshare. RsInit::InitRetroShare() returned " + ss.str() + "\n";
            return -1;
        }
    }
    return 0;
}
