#include "daemonsfile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool RsDaemonsFile::loadDaemonsFile(const std::string path, std::vector<DaemonAccount>& accounts, std::string &errString){
    FILE *f = fopen(path.c_str(),"rb");
    if(f == NULL){
        errString = "Could not open \"" + path + "\" for reading";
        return false;
    }
    fseek(f,0,SEEK_END);long len=ftell(f);fseek(f,0,SEEK_SET);
    char *data = (char*)malloc(len+1);fread(data,1,len,f);fclose(f);
    cJSON *root = cJSON_Parse(data);
    if(!root){
        errString = "Error parsing " + path + ":\n";
        errString += cJSON_GetErrorPtr();
        free(data);
        return false;
    }

    int numAccs = cJSON_GetArraySize(root);
    cJSON *currentAcc;
    bool allOk = true;
    std::string errstr = "";
    for(int i = 0; i < numAccs; i++){
        currentAcc = cJSON_GetArrayItem(root, i);
        bool accOk = true;
        accOk &= checkJSON(currentAcc, cJSON_True,      "enabled", errstr);
        accOk &= checkJSON(currentAcc, cJSON_String,    "preferred-user-id", errstr);
        accOk &= checkJSON(currentAcc, cJSON_String,    "ssl-password", errstr);
        accOk &= checkJSON(currentAcc, cJSON_True,      "ssh-enabled", errstr);
        accOk &= checkJSON(currentAcc, cJSON_String,    "ssh-user", errstr);
        accOk &= checkJSON(currentAcc, cJSON_String,    "ssh-passwordhash", errstr);
        accOk &= checkJSON(currentAcc, cJSON_Number,    "ssh-port", errstr);
        accOk &= checkJSON(currentAcc, cJSON_True,      "ssh-rpc-enabled", errstr);

        if(accOk){
            DaemonAccount acc;
            acc.enabled = cJSON_GetObjectItem(currentAcc, "enabled")->type;
            acc.preferred_user_id = cJSON_GetObjectItem(currentAcc, "preferred-user-id")->valuestring;
            acc.ssl_password = cJSON_GetObjectItem(currentAcc, "ssl-password")->valuestring;
            acc.ssh_enabled = cJSON_GetObjectItem(currentAcc, "ssh-enabled")->type;
            acc.ssh_user = cJSON_GetObjectItem(currentAcc, "ssh-user")->valuestring;
            acc.ssh_passwordhash = cJSON_GetObjectItem(currentAcc, "ssh-passwordhash")->valuestring;
            acc.ssh_port = cJSON_GetObjectItem(currentAcc, "ssh-port")->valueint;
            acc.ssh_rpc_enabled = cJSON_GetObjectItem(currentAcc, "ssh-rpc-enabled")->type;
            accounts.push_back(acc);
        }else{
            allOk = false;
        }
    }
    if(!allOk){
        errString = "Errors in \"" + path + "\":\n" + errstr;
    }
    free(data);
    return allOk;
}

bool RsDaemonsFile::saveDaemonsFile(const std::string path, const std::vector<DaemonAccount>& accounts, std::string &errString){
    FILE *f = fopen(path.c_str(), "wb");
    if(f == NULL){
        errString = "Could not open \"" + path + "\" for writing";
        return false;
    }

    cJSON *root = cJSON_CreateArray();
    for(int i = 0; i < accounts.size(); i++){
        DaemonAccount a = accounts[i];
        cJSON *acc = cJSON_CreateObject();
        cJSON_AddItemToArray(root, acc);
        if(a.enabled){
            cJSON_AddItemToObject(acc, "enabled", cJSON_CreateTrue());
        }else{
            cJSON_AddItemToObject(acc, "enabled", cJSON_CreateFalse());
        }
        cJSON_AddItemToObject(acc, "preferred-user-id", cJSON_CreateString(a.preferred_user_id.c_str()));
        cJSON_AddItemToObject(acc, "ssl-password", cJSON_CreateString(a.ssl_password.c_str()));
        if(a.ssh_enabled){
            cJSON_AddItemToObject(acc, "ssh-enabled", cJSON_CreateTrue());
        }else{
            cJSON_AddItemToObject(acc, "ssh-enabled", cJSON_CreateFalse());
        }
        cJSON_AddItemToObject(acc, "ssh-user", cJSON_CreateString(a.ssh_user.c_str()));
        cJSON_AddItemToObject(acc, "ssh-passwordhash", cJSON_CreateString(a.ssh_passwordhash.c_str()));
        cJSON_AddItemToObject(acc, "ssh-port", cJSON_CreateNumber(a.ssh_port));
        if(a.ssh_rpc_enabled){
            cJSON_AddItemToObject(acc, "ssh-rpc-enabled", cJSON_CreateTrue());
        }else{
            cJSON_AddItemToObject(acc, "ssh-rpc-enabled", cJSON_CreateFalse());
        }
    }
    char *data = cJSON_Print(root);
    fwrite(data, 1, strlen(data), f);
    fclose(f);
    free(data);
    cJSON_Delete(root);
    return true;
}

std::string RsDaemonsFile::encodeString(std::string input){
    std::string coded;
    for(int i = 0; i < input.length(); i++){
        char hi = ((input[i] >> 4)+'A');
        char low = ((input[i] & 0x0f)+'A');
        coded += hi;
        coded += low;
    }
    return coded;
}
std::string RsDaemonsFile::decodeString(std::string coded){
    std::string output;
    for(int i = 0; i < coded.length(); i += 2){
        output += ((coded[i]-'A') << 4) + ((coded[i+1]-'A'));
    }
    return output;
}

std::string RsDaemonsFile::getJSONType(int type){
    switch(type){
    case cJSON_False:
    case cJSON_True:
        return "Boolean";
    case cJSON_NULL:
        return "NULL";
    case cJSON_Number:
        return "Number";
    case cJSON_String:
        return "String";
    case cJSON_Array:
        return "Array";
    case cJSON_Object:
        return "Object";
    default:
        return "unknown";
    }
}

bool RsDaemonsFile::checkJSON(cJSON *c, int type, const std::string name, std::string &err){
    if(c == NULL){
        err += "object missing (pointer NULL)\n";
        return false;
    }
    if((c = cJSON_GetObjectItem(c, name.c_str())) == NULL){
        err += "\"" + name + "\" missing\n";
        return false;
    }
    if(         ((c->type == cJSON_False)||(c->type == cJSON_True))
            &&  ((type == cJSON_False)||(type == cJSON_True))){
        return true;
    }
    if(c->type != type){
        err += "\"" + name + "\" has wrong type. Its should be of type " + getJSONType(type)
                + " but is of type " + getJSONType(c->type) + "\n";
        return false;
    }
    return true;
}
