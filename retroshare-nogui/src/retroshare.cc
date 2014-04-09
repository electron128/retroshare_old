
/*
 * "$Id: retroshare.cc,v 1.4 2007-04-21 19:08:51 rmf24 Exp $"
 *
 * RetroShare C++ Interface.
 *
 * Copyright 2004-2006 by Robert Fernie.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License Version 2 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 *
 * Please report all bugs and problems to "retroshare@lunamutt.com".
 *
 */


#include <retroshare/rsiface.h>   /* definition of iface */
#include <retroshare/rsinit.h>   /* definition of iface */

#include "notifytxt.h"

#include <unistd.h>
#include <util/argstream.h>
#include <iostream>
#ifdef WINDOWS_SYS
#include <winsock2.h>
#endif
                                
#ifdef RS_INTRO_SERVER
#include "introserver.h"
#endif

#ifdef RS_SSH_SERVER
#include "ssh/rssshd.h"

#include "menu/menus.h"
#include "menu/stdiocomms.h"

#include "rpc/rpcsetup.h"

// NASTY GLOBAL VARIABLE HACK - NEED TO THINK OF A BETTER SYSTEM.
#include "rpc/proto/rpcprotosystem.h"

#endif

//   DAEMON
// http://www.enderunix.org/docs/eng/daemon.php
// http://www.netzmafia.de/skripten/unix/linux-daemon-howto.html
//-----------
// openssl+fork may lead to bad random numbers
// don't know what to do about this.
//  see http://wiki.openssl.org/index.php/Random_fork-safety
//
// the ssl-password is stored in a file
// better make sure this file is readable by the owner only
//
// maybe a problem: hardcoded /.retroshare everywhere
//                  would be better if retroshare basedir would come from a single variable
// maybe catch the sigterm signal and shutdown rs like the gui does
//  see http://airtower.wordpress.com/2010/06/16/catch-sigterm-exit-gracefully/
// note: preferred with 2x'r'
// todo: find out why start failed and tell user (maybe logfile)
// idea: remove all ssh specific code from daemon code
//       to allow other services like chatserver use the daemon code
// maybe create the possibility to view status/pid of running instances. don't know if useful?
// maybe allow startup/shutdown of a single instance.

#ifdef ENABLE_DAEMON
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include "daemon/cJSON.h"
#include "daemon/daemonsfile.h"
#include <util/rsdir.h>
#endif

#ifdef RS_SSH_SERVER
void generatePasswordHash() ;
#endif

/* Basic instructions for running libretroshare as background thread.
 * ******************************************************************* *
 * This allows your program to communicate with authenticated peers. 
 *
 * libretroshare's interfaces are defined in libretroshare/src/rsiface.
 * This should be the only headers that you need to include.
 *
 * The startup routine's are defined in rsiface.h
 */

int main(int argc, char **argv)
{
	/* Retroshare startup is configured using an RsInit object.
	 * This is an opaque class, which the user cannot directly tweak
	 * If you want to peek at whats happening underneath look in
	 * libretroshare/src/rsserver/p3face-startup.cc
	 *
	 * You create it with InitRsConfig(), and delete with CleanupRsConfig()
	 * InitRetroshare(argv, argc, config) parses the command line options, 
	 * and initialises the config paths.
	 *
	 * *** There are several functions that I should add to modify 
	 * **** the config the moment these can only be set via the commandline 
	 *   - RsConfigDirectory(...) is probably the most useful.
	 *   - RsConfigNetAddr(...) for setting port, etc.
	 *   - RsConfigOutput(...) for logging and debugging.
	 *
	 * Next you need to worry about loading your certificate, or making
	 * a new one:
	 *
	 *   RsGenerateCertificate(...) To create a new key, certificate 
	 *   LoadPassword(...) set password for existing certificate.
	 **/

	bool strictCheck = true;

#ifdef RS_SSH_SERVER
	/* parse commandline for additional nogui options */

	int c;
	// libretroshare's getopt str - so don't use any of these: "hesamui:p:c:w:l:d:U:r:R:"
	// need options for 
	// enable SSH.   (-S)
	// set user/password for SSH. -L "user:pwdhash"
	// accept RSA Key Auth. -K "RsaPubKeyFile"
	// Terminal mode. -T 
	bool enableRpc = false;
	bool enableSsh = false;
	bool enableSshHtml = false;
	bool enableTerminal = false;
	bool enableSshRsa = false;
	bool genPwdHash = false;
	std::string sshUser = "user";
	std::string sshPwdHash = "";
	std::string sshRsaFile = "";

	uint16_t extPort = 0;
	uint16_t sshPort = 7022;
	bool     extPortSet = false;
	bool displayRPCInfo = false ;

#ifdef ENABLE_DAEMON
    std::string daemonAction = ""; // "start","stop","help","enable","disable" or "" for not running as daemon
    std::string SSLPassword;
    std::vector<RsDaemonsFile::DaemonAccount> daemonAccounts;
    std::string pathToDaemonsFile;
#endif

	argstream as(argc,argv) ;

	as >> option('X',"enable-ssh"     ,enableSsh        ,"Enable SSH"        )
	   >> option('T',"enable-terminal",enableTerminal   ,"Enable terminal interface."  )
		>> option('C',"enable-rpc"     ,enableRpc        ,"Enable RPC protocol. To be used with e.g. -X (SSH).")
	   >> option('G',"gen-password"   ,genPwdHash       ,"Generate password hash (to supply to option -P)")
#if 0
	   >> option('H',"enable-ssh-html",enableSshHtml    ,"Enable SSH html."  )
#endif
	   >> parameter('S',"ssh-port"       ,sshPort       ,"port"  ,"SSH port to contact the interface.",false)
	   >> parameter('E',"ext-port"       ,extPort       ,"port"  ,"Specify Alternative External Port (provided to Clients)",false)
	   >> parameter('L',"ssh-user"       ,sshUser       ,"name"  ,"Ssh login user",false)
       >> parameter('P',"ssh-p-hash"     ,sshPwdHash    ,"hash"  ,"Ssh login password hash (Generated by retroshare-nogui -G)",false)
	   >> parameter('K',"ssh-key-file"   ,sshRsaFile    ,"RSA key file", "RSA key file for SSH login (not yet implemented).",false  )// NOT FINISHED YET.

#ifdef ENABLE_DAEMON
       >> parameter(0 ,"daemon"          ,daemonAction  ,"start/stop/enable/disable/help","Start to background or stop running instance. Use \"--daemon help\" to view more info.", false)
#endif
		>> help() ;

	// Normally argstream would handle this by itself, if we called
	// 	as.defaultErrorHandling() ;
	//
	// but we have other parameter handling functions after, so we don't want to quit if help is requested.
	//
	if (as.helpRequested())
	{
		std::cerr << "\nSpecific Help Options:" << std::endl;
		std::cerr << as.usage() << std::endl;
		std::cerr << "\t To setup rs-nogui as a SSH Server is a three step process: " << std::endl;
		std::cerr << "\t 1) Generate a RSA keypair in the current directory: \"ssh-keygen -t rsa -f rs_ssh_host_rsa_key\" " << std::endl;
		std::cerr << "\t 2) Generate a password hash for the RPC login:      \"./retroshare-nogui -G\" " << std::endl;
		std::cerr << "\t 3) Launch the RS with remote control enabled:       \"./retroshare-nogui -X/-T [-C] -S [port] -L <user> -P <passwordhash>\" " << std::endl;

		std::cerr << "\nAdditional options: \n" << std::endl;
	}
	if (!as.isOk())
	{
		 std::cerr << as.errorLog();
		 return 1; 
	}
#ifdef ENABLE_DAEMON
    if (daemonAction == "help")
    {
        std::cerr << "Run Retroshare as daemon in the background" << std::endl;
        std::cerr << "to prepare an account run" << std::endl;
        std::cerr << "  retroshare-nogui --daemon enable" << std::endl;
        std::cerr << "you can use these additional options to specify how retroshare-nogui will run:" << std::endl;
        std::cerr << "  -U/--user-id <name/pgp-id/ssl-id> Specify the Account" << std::endl;
        std::cerr << "  -X/--enable-ssh    Enable SSH" << std::endl;
        std::cerr << "  -S/--ssh-port      SSH Port to contact the Interface" << std::endl;
        std::cerr << "  -L/--ssh-user      SSH login user (default=user)" << std::endl;
        std::cerr << "  -P/--ssh-p-hash    SSH login password hash (Generated by retroshare-nogui -G)" << std::endl;
        std::cerr << "  -C/--enable-rpc    Enable RPC protocol. To be used with -X (SSH)" << std::endl;
        std::cerr << "" << std::endl;
        std::cerr << "to remove an account from the list of daemons" << std::endl;
        std::cerr << "  retroshare-nogui --daemon disable (--user-id <...>)" << std::endl;
        std::cerr << "" << std::endl;
        std::cerr << "start the daemons:" << std::endl;
        std::cerr << "  retroshare-nogui --daemon start" << std::endl;
        std::cerr << "stop the daemons:" << std::endl;
        std::cerr << "  retroshare-nogui --daemon stop" << std::endl;
        std::cerr << "" << std::endl;
        std::cerr << "run as root to start/stop for all users" << std::endl;
        std::cerr << "" << std::endl;
        std::cerr << "run the follwing command to enable automatic start at boot:" << std::endl;
        std::cerr << "  sudo update-rc.d retroshare defaults" << std::endl;
        std::cerr << "to disable start at boot" << std::endl;
        std::cerr << "  sudo update-rc.d retroshare remove" << std::endl;
        return 0;
    }
#endif

	if (genPwdHash)
	{
		generatePasswordHash() ;
		return 0 ;
    }

	/* enforce conditions */
	if ((!sshRsaFile.empty() || !sshPwdHash.empty()) && (!enableSsh))
	{
		std::cerr << "ERROR: SSH Server (-X) must be enabled to specify SSH Pwd (-P) or SSH RSA (-K)";
		std::cerr << std::endl;
		return 1 ;
	}

	if (enableSsh && (!enableSshRsa) && sshPwdHash.empty())
	{
		std::cerr << "ERROR: One of (or both) SSH Pwd (-P) and SSH RSA (-K) must be specified with SSH Server (-X)";
		std::cerr << std::endl;
		return 1 ;
	}

	if (enableRpc && (!enableSsh))
	{
		std::cerr << "ERROR: RPC Mode (-C) requires SSH Server (-X) enabled";
		std::cerr << std::endl;
		return 1 ;
	}


	/* parse -S, -L & -K parameters */
	if (enableSshRsa)
	{
		/* check the file exists */
		/* TODO */

	}

	if (enableSsh)
	{
		/* try parse it */
		/* TODO */

	}

#else
	std::cerr << "\nRetroshare command line interface." << std::endl;
#endif

#ifdef ENABLE_DAEMON
    const uint8_t PIPEMSG_SUCCESS  = 0;
    const uint8_t PIPEMSG_FAIL     = 1;

    int pipeToParent = 0;
    int pipeFromChild = 0;
    if ((getuid() == 0)&&((daemonAction == "start")||(daemonAction == "stop")))// running as root
    {
        std::cerr << "running as root" << std::endl;
        passwd *passwdentry;
        bool allOk = true;

        // loop through all users
        // if pipeToParent=/=0, then we are not root anymore and should continue
        // (and really start retroshare)
        while((passwdentry = getpwent()) && (pipeToParent == 0))
        {
            struct stat statbuf;
            std::string rsdir = std::string(passwdentry->pw_dir) + "/.retroshare";
            //std::cerr << "checking directory \"" << rsdir << "\"" << std::endl;
            if(stat(rsdir.c_str(), &statbuf) == -1){
                //std::cerr << "stat(" << rsdir << ") failed" << std::endl;
                continue;
            }
            if(S_ISDIR(statbuf.st_mode)){
                //std::cerr << "Found directory: " << rsdir << std::endl;
                int pipefd[2];
                if(pipe(pipefd) == -1){
                    std::cerr << "Error: could not create Pipe" << std::endl;
                    return 1;
                }
                pipeFromChild = pipefd[0];
                pipeToParent = pipefd[1];

                pid_t pid;
                pid = fork();
                if(pid == -1){
                    std::cerr << "Error: could not fork" << std::endl;
                    return 1;
                }
                if(pid > 0){
                    // parent process
                    close(pipeToParent);
                    pipeToParent = 0;

                    uint8_t val = 0;
                    read(pipeFromChild, &val, 1);
                    if(val == PIPEMSG_FAIL){
                        allOk = false;
                    }
                    close(pipeFromChild);
                    //std::cerr << "root prcess: forked a child and got pipemsg" << std::endl;
                }
                if(pid == 0){
                    // child process
                    close(pipeFromChild);
                    pipeFromChild = 0;
                    // setsid, and chdir not needed, because this process will fork itself again
                    // and exit before the parent(=root) process

                    gid_t *groupIdList;
                    int numGroups = 0;

                    // Overview:
                    // 1. set supplementary group ids
                    // 2. set main group id
                    // 3. set user id, this has to be done at last, because it drops all root privileges

                    // first get number of groups, to find out how much memory we need
                    getgrouplist(passwdentry->pw_name, passwdentry->pw_gid, groupIdList, &numGroups);
                    groupIdList = (gid_t*) malloc(numGroups * sizeof(gid_t));
                    getgrouplist(passwdentry->pw_name, passwdentry->pw_gid, groupIdList, &numGroups);

                    if(setgroups(numGroups, groupIdList) == -1){
                        std::cerr << "Error: setgroups() returned -1" << std::endl;
                        free(groupIdList);
                        write(pipeToParent, &PIPEMSG_FAIL, 1);
                        close(pipeToParent);
                        return 1;
                    }
                    free(groupIdList);

                    if(setgid(passwdentry->pw_gid) == -1){
                        std::cerr << "Error: setgid() returned -1" << std::endl;
                        write(pipeToParent, &PIPEMSG_FAIL, 1);
                        close(pipeToParent);
                        return 1;
                    }
                    if(setuid(passwdentry->pw_uid) == -1){
                        std::cerr << "Error: setuid() returned -1" << std::endl;
                        write(pipeToParent, &PIPEMSG_FAIL, 1);
                        close(pipeToParent);
                        return 1;
                    }

                    // from here we will continue as if we where started as a normal user
                    // we only have to report back to the root process when we are done
                }

            }
        }
        // if we are the root process, we want to exit
        if(pipeToParent == 0){
            if(allOk){
                std::cerr << "retroshare-nogui root process: Everything ok" << std::endl;
                return 0;
            } else {
                std::cerr << "retroshare-nogui root process: Something failed" << std::endl;
                return 1;
            }
        }
    }

    // prepare path to daemons file
    if(daemonAction != ""){
        char *homeDir = getenv("HOME");
        if (homeDir == NULL){
            std::cerr << "Error: getenv(\"HOME\") returned NULL" << std::endl;
            if(pipeToParent != 0){
                write(pipeToParent, &PIPEMSG_FAIL, 1);
                close(pipeToParent);
            }
            return 1;
        }
        pathToDaemonsFile = std::string(homeDir) + "/.retroshare/daemons.txt";
        std::string errStr;
        if(RsDaemonsFile::loadDaemonsFile(pathToDaemonsFile, daemonAccounts, errStr)){
            std::cerr << "read \"" << pathToDaemonsFile << "\", Number of Accounts:" << daemonAccounts.size() << std::endl;
        }else{
            std::cerr << "Error reading daemonsfile: " << errStr << std::endl;
            std::cerr << "use \"retroshare-nogui --daemon enable\" to create one"<< std::endl;
            if(pipeToParent != 0){
                write(pipeToParent, &PIPEMSG_FAIL, 1);
                close(pipeToParent);
            }
            return 1;
        }
    }

    // if we reach here we are running as a normal user and want to start/stop instances of retroshare
    if((daemonAction == "start")||(daemonAction == "stop")){
        bool isChild = false;
        bool allOk = true;
        for(unsigned int i = 0; (i < daemonAccounts.size())&&(isChild == false);i++){
            // fork, setsid, umask, chwd, close stdin/stdout/stderr
            // start retroshare
            RsDaemonsFile::DaemonAccount currentAcc = daemonAccounts[i];
            if(currentAcc.enabled){
                int pipefd[2];
                if(pipe(pipefd) == -1){
                    std::cerr << "Error: could not create Pipe" << std::endl;
                    if(pipeToParent != 0){
                        write(pipeToParent, &PIPEMSG_FAIL, 1);
                        close(pipeToParent);
                    }
                    return 1;
                }

                pid_t pid, sid;
                pid = fork();
                if(pid == -1){
                    std::cerr << "Error: could not fork" << std::endl;
                    if(pipeToParent != 0){
                        write(pipeToParent, &PIPEMSG_FAIL, 1);
                        close(pipeToParent);
                    }
                    return 1;
                }
                if(pid > 0){
                    // parent process
                    close(pipefd[1]);
                    uint8_t val = 0;
                    read(pipefd[0], &val, 1);
                    //std::cerr << "parent process: got msg from child: " << (int)val << std::endl;
                    if(val == PIPEMSG_SUCCESS){
                        if(daemonAction == "start"){
                            std::cerr << "started retroshare-nogui for user " << getlogin()
                                      << " account:" << currentAcc.preferred_user_id
                                      << " pid:" << pid << std::endl;
                        } else{
                            std::cerr << "stopped retroshare-nogui for user " << getlogin()
                                      << " account:" << currentAcc.preferred_user_id
                                      << std::endl;
                        }
                    } else {
                        allOk = false;
                        if(daemonAction == "start"){
                            std::cerr << "failed to start account " << currentAcc.preferred_user_id
                                      << " for user " << getlogin() << std::endl;
                        } else {
                            std::cerr << "failed to stop account " << currentAcc.preferred_user_id
                                      << " for user " << getlogin() << std::endl;
                        }

                    }
                    close(pipefd[0]);
                }
                if(pid == 0){
                    // child process
                    isChild = true;
                    close(pipefd[0]);
                    if(pipeToParent != 0){// check if we have pipe to root process
                        close(pipeToParent);
                    }
                    pipeToParent = pipefd[1];

                    sid = setsid();
                    if(sid == -1){
                        std::cerr << "Error: setsid() returned -1" << std::endl;
                        write(pipeToParent, &PIPEMSG_FAIL, 1);
                        close(pipeToParent);
                        return 1;
                    }
                    if(chdir("/") == -1){
                        std::cerr << "Error: could not change working directory" << std::endl;
                        write(pipeToParent, &PIPEMSG_FAIL, 1);
                        close(pipeToParent);
                        return 1;
                    }

                    // umask is not necessary, because we run as normal user
                    // umask()

                    close(STDIN_FILENO);
                    close(STDOUT_FILENO);
                    close(STDERR_FILENO);

                    // prepare startup with values from daemons.txt
                    RsInit::setPreferedUserString(currentAcc.preferred_user_id);
                    SSLPassword = RsDaemonsFile::decodeString(currentAcc.ssl_password);
                    if(currentAcc.ssh_enabled){
                        enableSsh   = true;
                        sshUser     = currentAcc.ssh_user;
                        sshPwdHash  = currentAcc.ssh_passwordhash;
                        sshPort     = currentAcc.ssh_port;
                        if(currentAcc.ssh_rpc_enabled){
                            enableRpc   = true;
                        }
                    }
                }
            }
        }

        // exit if not a child process
        if(isChild == false){
            if(allOk){
                if(pipeToParent != 0){// send msg to root process
                    write(pipeToParent, &PIPEMSG_SUCCESS, 1);
                    close(pipeToParent);
                } else {
                    std::cerr << "daemon: Everything ok" << std::endl;
                }
                return 0;
            } else {
                if(pipeToParent != 0){
                    write(pipeToParent, &PIPEMSG_FAIL, 1);
                    close(pipeToParent);
                } else {
                    std::cerr << "daemon: Something failed" << std::endl;
                }
                return 1;
            }
        }
    }

#endif // ENABLE_DAEMON


	RsInit::InitRsConfig();
	int initResult = RsInit::InitRetroShare(argc, argv, strictCheck);

	if (initResult < 0) {
		/* Error occured */
		switch (initResult) {
		case RS_INIT_AUTH_FAILED:
			std::cerr << "RsInit::InitRetroShare AuthGPG::InitAuth failed" << std::endl;
			break;
		default:
			/* Unexpected return code */
			std::cerr << "RsInit::InitRetroShare unexpected return code " << initResult << std::endl;
			break;
		}

#ifdef ENABLE_DAEMON
        if(pipeToParent != 0){
            write(pipeToParent, &PIPEMSG_FAIL, 1);
            close(pipeToParent);
        }
#endif
		return 1;
	}

	 /* load password should be called at this point: LoadPassword()
	  * otherwise loaded from commandline.
	  */


	/* Now setup the libretroshare interface objs 
	 * You will need to create you own NotifyXXX class
	 * if you want to receive notifications of events */

	// This is needed to allocate rsNotify, so that it can be used to ask for PGP passphrase
	//
	RsControl::earlyInitNotificationSystem() ;

	NotifyTxt *notify = new NotifyTxt() ;
#ifdef ENABLE_DAEMON
	if((daemonAction == "start")||(daemonAction == "stop")){
		notify->silentMode = true;
	}
#endif
	rsNotify->registerNotifyClient(notify);

	std::string preferredId, gpgId, gpgName, gpgEmail, sslName;
	RsInit::getPreferedAccountId(preferredId);

	if (RsInit::getAccountDetails(preferredId, gpgId, gpgName, gpgEmail, sslName))
	{
		RsInit::SelectGPGAccount(gpgId);
	}

#ifdef ENABLE_DAEMON
    //std::cerr << "loading raw SSL-Password:" << SSLPassword << std::endl;
    RsInit::LoadPassword(preferredId, SSLPassword);
    if(daemonAction == "enable"){
        std::string pwd = RsInit::getSSLPassword();
        RsDaemonsFile::DaemonAccount acc;
        unsigned int i;
        bool found = false;
        for(i = 0; i < daemonAccounts.size(); i++){
            acc = daemonAccounts[i];
            if(acc.preferred_user_id == preferredId){
                found = true;
                break;
            }
        }
        acc.enabled = true;
        acc.preferred_user_id = preferredId;
        // encode to make a cleaner string
        acc.ssl_password = RsDaemonsFile::encodeString(pwd);
        acc.ssh_enabled = enableSsh;
        acc.ssh_user = sshUser;
        acc.ssh_passwordhash = sshPwdHash;
        acc.ssh_port = sshPort;
        acc.ssh_rpc_enabled = enableRpc;
        if(found){
            daemonAccounts[i] = acc;
        }else{
            daemonAccounts.push_back(acc);
        }
        std::string errStr;
        if(RsDaemonsFile::saveDaemonsFile(pathToDaemonsFile, daemonAccounts, errStr)){
            std::cerr << "wrote daemonsfile" << std::endl;
        }else{
            std::cerr << "error writing daemonsfile: " << errStr << std::endl;
        }
        return 0;
    }
    if(daemonAction == "disable"){
        RsDaemonsFile::DaemonAccount acc;
        unsigned int i;
        bool found = false;
        for(i = 0; i < daemonAccounts.size(); i++){
            acc = daemonAccounts[i];
            if(acc.preferred_user_id == preferredId){
                found = true;
                break;
            }
        }
        acc.enabled = false;
        // remove ssl-password
        acc.ssl_password = "";
        if(found){
            daemonAccounts[i] = acc;
            std::string errStr;
            if(RsDaemonsFile::saveDaemonsFile(pathToDaemonsFile, daemonAccounts, errStr)){
                std::cerr << "wrote daemonsfile" << std::endl;
            }else{
                std::cerr << "error writing daemonsfile: " << errStr << std::endl;
            }
        }else{
            std::cerr << "account not found in daemons.txt" << std::endl;
        }
        return 0;
    }
#endif

	/* Key + Certificate are loaded into libretroshare */

    std::string lockFilePath ;
    pid_t runningInstancePid;
    int retVal = RsInit::LockAndLoadCertificates(false,lockFilePath,runningInstancePid);
	switch(retVal)
	{
		case 0:	break;
        case 1:
#ifdef ENABLE_DAEMON
                if(daemonAction == "stop"){
                    kill(runningInstancePid, SIGTERM);
                    // wait for process to finish
                    pid_t pid; rs_lock_handle_t lockFileHandle;
                    while(RsDirUtil::createLockFile(lockFilePath, lockFileHandle, pid)==1){
                        usleep(500);// wait for xx microseconds
                    }
                    write(pipeToParent, &PIPEMSG_SUCCESS, 1);
                    close(pipeToParent);
                    return 1;
                }
#endif
                std::cerr << "Error: another instance of retroshare is already using this profile" << std::endl;
                break;
		case 2: std::cerr << "An unexpected error occurred while locking the profile" << std::endl;
                break;
		case 3: std::cerr << "An error occurred while login with the profile" << std::endl;
                break;
		default: std::cerr << "Main: Unexpected switch value " << retVal << std::endl;
                break;
	}
#ifdef ENABLE_DAEMON
    if(retVal != 0){
        write(pipeToParent, &PIPEMSG_FAIL, 1);
        close(pipeToParent);
        return 1;
    } else {
        write(pipeToParent, &PIPEMSG_SUCCESS, 1);
        close(pipeToParent);
    }
#endif
    if(retVal != 0){
        return 1;
    }

#ifdef RS_SSH_SERVER
	// Says it must be called before all the threads are launched! */
        // NB: this port number is not currently used.
	RsSshd *ssh = NULL;

	if (enableSsh)
	{
		std::ostringstream os ;
		os << sshPort ;
		ssh = RsSshd::InitRsSshd(os.str(), "rs_ssh_host_rsa_key");

		// TODO Parse Option
		if (enableSshRsa)
		{
        		//ssh->adduser("anrsuser", "test");
		}

		if (!sshPwdHash.empty())
		{
        		ssh->adduserpwdhash(sshUser, sshPwdHash);
		}
			
		if (!extPortSet)
		{
			extPort = sshPort;
		}

		// NASTY GLOBAL VARIABLE HACK - NEED TO THINK OF A BETTER SYSTEM.
		RpcProtoSystem::mExtPort = extPort;
	}
#endif

	/* Start-up libretroshare server threads */
	RsControl::instance() -> StartupRetroShare();

#ifdef RS_INTRO_SERVER
	RsIntroServer rsIS;
#endif
	
#ifdef RS_SSH_SERVER
	uint32_t baseDrawFlags = 0;
	if (enableSshHtml)
	{
		baseDrawFlags = MENU_DRAW_FLAGS_HTML;
	}

	if (enableSsh)
	{
		if (enableRpc)
		{
			/* Build RPC Server */
			RpcMediator *med = CreateRpcSystem(ssh, notify);
			ssh->setRpcSystem(med);
			ssh->setSleepPeriods(0.01, 0.1);
		}
		else
		{
			/* create menu system for SSH */
			Menu *baseMenu = CreateMenuStructure(notify);
			MenuInterface *menuInterface = new MenuInterface(ssh, baseMenu, baseDrawFlags | MENU_DRAW_FLAGS_ECHO);
			ssh->setRpcSystem(menuInterface);
			ssh->setSleepPeriods(0.05, 0.5);
		}
	
		ssh->start();
	}

	MenuInterface *terminalMenu = NULL;
	if (enableTerminal)
	{
		/* Terminal Version */
		RpcComms *stdioComms = new StdioComms(fileno(stdin), fileno(stdout)); 
		Menu *baseMenu = CreateMenuStructure(notify);
		terminalMenu = new MenuInterface(stdioComms, baseMenu, baseDrawFlags | MENU_DRAW_FLAGS_NOQUIT);
		//menuTerminal = new RsConsole(menuInterface, fileno(stdin), fileno(stdout));
	}


#endif

	/* pass control to the GUI */
	while(1)
	{
		//std::cerr << "GUI Tick()" << std::endl;

#ifdef RS_INTRO_SERVER
		rsIS.tick();
#endif

		int rt = 0;
#ifdef RS_SSH_SERVER
		if (terminalMenu)
		{
			rt = terminalMenu->tick();
		}
#endif

		// If we have a MenuTerminal ...
		// only want to sleep if there is no input. (rt == 0).
		if (rt == 0)
		{
#ifndef WINDOWS_SYS
			sleep(1);
#else
			Sleep(1000);
#endif
		}

        usleep(1000);

	}
	return 1;
}

#ifdef RS_SSH_SERVER
void generatePasswordHash()
{
	std::string saltBin;
	std::string pwdHashRadix64;
	std::string sshPwdForHash = "";

	std::string passwd1,passwd2 ;

	if(!NotifyTxt().askForPassword("Type your password (at least 8 chars) : ",false,passwd1)) exit(1) ;

	if(passwd1.length() < 8)
	{
		std::cerr << "Password must be at least 8 characters long." << std::endl;
		exit(1);
	}

	if(!NotifyTxt().askForPassword("Type your password (checking)         : ",false,passwd2)) exit(1) ;

	if(passwd1 != passwd2)
	{
		std::cerr << "Passwords differ. Please retry." << std::endl;
		exit(1);
	}

	sshPwdForHash = passwd1 ;

	//std::cerr << "Chosen Password : " << sshPwdForHash;
	std::cerr << std::endl;

	GenerateSalt(saltBin);
	if (!GeneratePasswordHash(saltBin, sshPwdForHash, pwdHashRadix64))
	{
		std::cerr << "Error Generating Password Hash, password probably too short";
		std::cerr << pwdHashRadix64;
		std::cerr << std::endl;
		exit(1);
	}

	std::cout << "Generated Password Hash for rs-nogui: ";
	std::cout << pwdHashRadix64;
	std::cout << std::endl;
	std::cout << std::endl;

	/* checking match */
	if (CheckPasswordHash(pwdHashRadix64, sshPwdForHash))
	{
		std::cerr << "Passed Check Okay!";
		std::cerr << std::endl;
	}
	else
	{
		std::cerr << "ERROR: Failed CheckPassword!";
		std::cerr << std::endl;
		exit(1);
	}


	std::cerr << "Usage:";
	std::cerr << std::endl;
	std::cerr << " - for SSH access: ./retroshare-nogui    -X -S [port] -L <username> -P " << pwdHashRadix64;
	std::cerr << std::endl;
	std::cerr << " - for RPC access: ./retroshare-nogui -C -X -S [port] -L <username> -P " << pwdHashRadix64;
	std::cerr << std::endl;
}
#endif
	
