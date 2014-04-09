#ifndef DAEMONSFILE_H
#define DAEMONSFILE_H

#include <string>
#include <vector>
#include "cJSON.h"

namespace RsDaemonsFile{

    class DaemonAccount{
    public:
        bool enabled;
        std::string preferred_user_id;
        std::string ssl_password;
        bool ssh_enabled;
        std::string ssh_user;
        std::string ssh_passwordhash;
        int ssh_port;
        bool ssh_rpc_enabled;
    };

    bool loadDaemonsFile(const std::string path, std::vector<DaemonAccount>& accounts, std::string &errString);
    bool saveDaemonsFile(const std::string path, const std::vector<DaemonAccount>& accounts, std::string &errString);

    // converst each nible to an ascii character >='A'
    std::string encodeString(std::string input);
    std::string decodeString(std::string coded);

    // get a human readable description of the cJSON type
    std::string getJSONType(int type);
    // check if the element exists and if it has the correct type
    bool checkJSON(cJSON *c, int type, const std::string name, std::string &err);
}

#endif // DAEMONSFILE_H
