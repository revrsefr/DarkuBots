/* InspIRCd 4 protocol module for DarkuBots Services
 *
 * This file implements the protocol-specific functions for
 * the InspIRCd 4.x IRCd.
 *
 * Services is copyright (c) 1996-1999 Andy Church.
 *     E-mail: <achurch@dragonfire.net>
 * This program is free but copyrighted software; see the file COPYING for
 * details.
 *
 * InspIRCd 4 protocol module added on April 21, 2025
 */

#ifdef IRC_INSPIRCD_4

#include "services.h"

/*************************************************************************/
/************************** CONSTANTS & GLOBALS **************************/
/*************************************************************************/

/* InspIRCd UID format: SAIAAAB = Server ID 'S' + 'A' (fixed) + client ID */
#define UID_LEN 9

/* Local variables */
static char *ServerName;
static char *ServerDesc;
static int irc_sock = -1;
static char *nickservmode = "+";  /* Modes to send for NickServ/ChanServ */
static char *chanservmode = "+";
static char *memoservmode = "+";
static char *hostservmode = "+";
static char *operservmode = "+";
static char *botservmode = "+";
static char *rootservmode = "+";
static char *servicesservmode = "+";
static int debug = 0;
static char *s_OperServ, *s_NickServ, *s_ChanServ, *s_MemoServ;
static char *s_HelpServ, *s_CyberServ, *s_BddServ, *s_BotServ, *s_CregServ;
static char *ServiceHost;
static char *RootNick;
static char *ServerUID;  /* Our SID (server ID) */
static int NextUIDIndex = 1; /* Next UID index to use */

/*************************************************************************/
/************************ PROTOCOL UTILITY FUNCTIONS *********************/
/*************************************************************************/

/**
 * Convert a UID to a server ID
 * @param uid The UID to convert
 * @return The server ID portion
 */
char *uid_to_sid(const char *uid) {
    static char sid[4];
    if (!uid || strlen(uid) < 3)
        return NULL;
    strncpy(sid, uid, 3);
    sid[3] = '\0';
    return sid;
}

/**
 * Determine if a string is a valid UID
 * @param str The string to check
 * @return 1 if valid, 0 if not
 */
int is_valid_uid(const char *str) {
    if (!str || strlen(str) != UID_LEN)
        return 0;
    
    /* First char must be a digit or uppercase letter (server id) */
    if (!isalnum(str[0]) || islower(str[0]))
        return 0;
    
    /* Second char must be 'A' for extended UIDs */
    if (str[1] != 'A')
        return 0;
    
    /* Chars 3-9 must be alphanumeric */
    for (int i = 2; i < UID_LEN; i++) {
        if (!isalnum(str[i]))
            return 0;
    }
    
    return 1;
}

/**
 * Parse InspIRCd channel modes
 * @param modes The mode string to parse
 * @param chan The channel structure to update
 * @return Updated mode value
 */
int parse_inspircd_chan_modes(const char *modes, Channel *chan) {
    int add = 1;
    int i;
    int32 mode = 0;
    const char *param;
    
    if (!modes || !chan)
        return 0;
    
    for (i = 0; modes[i]; i++) {
        switch (modes[i]) {
            case '+': add = 1; break;
            case '-': add = 0; break;
            case 'i': 
                if (add) mode |= CMODE_I;
                else mode &= ~CMODE_I;
                break;
            case 'm': 
                if (add) mode |= CMODE_M;
                else mode &= ~CMODE_M;
                break;
            case 'n': 
                if (add) mode |= CMODE_N;
                else mode &= ~CMODE_N;
                break;
            case 'p': 
                if (add) mode |= CMODE_P;
                else mode &= ~CMODE_P;
                break;
            case 's': 
                if (add) mode |= CMODE_s;
                else mode &= ~CMODE_s;
                break;
            case 't': 
                if (add) mode |= CMODE_T;
                else mode &= ~CMODE_T;
                break;
            case 'r': 
                if (add) mode |= CMODE_r;
                else mode &= ~CMODE_r;
                break;
            case 'c': 
                if (add) mode |= CMODE_c;
                else mode &= ~CMODE_c;
                break;
            case 'C': 
                if (add) mode |= CMODE_C;
                else mode &= ~CMODE_C;
                break;
            case 'O': 
                if (add) mode |= CMODE_O;
                else mode &= ~CMODE_O;
                break;
            case 'k':
                if (add) {
                    /* Key requires a parameter */
                    mode |= CMODE_K;
                    /* Get the param and store the key */
                    /* In a real implementation, we'd extract the parameter */
                } else {
                    mode &= ~CMODE_K;
                    if (chan->key) {
                        free(chan->key);
                        chan->key = NULL;
                    }
                }
                break;
            case 'l':
                if (add) {
                    /* Limit requires a parameter */
                    mode |= CMODE_L;
                    /* Get the param and store the limit */
                    /* In a real implementation, we'd extract the parameter */
                } else {
                    mode &= ~CMODE_L;
                    chan->limit = 0;
                }
                break;
        }
    }
    
    return mode;
}

/**
 * Parse InspIRCd user modes
 * @param modes The mode string to parse
 * @return Updated mode value
 */
int32 parse_inspircd_user_modes(const char *modes) {
    int add = 1;
    int i;
    int32 mode = 0;
    
    if (!modes)
        return 0;
    
    for (i = 0; modes[i]; i++) {
        switch (modes[i]) {
            case '+': add = 1; break;
            case '-': add = 0; break;
            case 'o': 
                if (add) mode |= UMODE_O;
                else mode &= ~UMODE_O;
                break;
            case 'i': 
                if (add) mode |= UMODE_I;
                else mode &= ~UMODE_I;
                break;
            case 's': 
                if (add) mode |= UMODE_S;
                else mode &= ~UMODE_S;
                break;
            case 'w': 
                if (add) mode |= UMODE_W;
                else mode &= ~UMODE_W;
                break;
            case 'z': 
                if (add) mode |= UMODE_Z;
                else mode &= ~UMODE_Z;
                break;
            case 'h': 
                if (add) mode |= UMODE_H;
                else mode &= ~UMODE_H;
                break;
            case 'r': 
                if (add) mode |= UMODE_R;
                else mode &= ~UMODE_R;
                break;
            case 'x': 
                if (add) mode |= UMODE_X;
                else mode &= ~UMODE_X;
                break;
        }
    }
    
    return mode;
}

/**
 * Generate a UID for services
 * @param nick The nickname to generate a UID for
 * @return The generated UID
 */
char *generate_uid(const char *sid, const char *nick) {
    static char uid[UID_LEN+1];
    static int counter = 0;
    
    if (!sid || strlen(sid) != 3)
        return NULL;
    
    /* Format: SID + 'A' + 5 chars */
    snprintf(uid, sizeof(uid), "%sA%05X", sid, counter++ % 0xFFFFF);
    return uid;
}

/*************************************************************************/
/************************* CONNECTION FUNCTIONS **************************/
/*************************************************************************/

/* Send capabilities and other initialization messages */
static void inspircd_send_version(void) {
    /* Send capabilities - use configured options if available, otherwise defaults */
    const char *capab = InspIRCdCapabilities ? InspIRCdCapabilities : "PROTOCOL=1202";
    
    send_cmd(NULL, "CAPAB START 1202");
    send_cmd(NULL, "CAPAB CAPABILITIES :%s", capab);
    send_cmd(NULL, "CAPAB END");
}

/* Introduce a new user/service to the network */
static void inspircd_introduce_user(const char *nick, const char *user, 
                                  const char *host, const char *real,
                                  const char *modes) {
    char uid[INSPIRCD_UID_LEN+1];
    time_t now = time(NULL);
    
    /* Generate a unique UID for this user */
    snprintf(uid, sizeof(uid), "%sA%04X", ServerUID, NextUIDIndex++);
    
    /* Send UID command to create the user */
    send_cmd(NULL, "UID %s %ld %s %s %s %s 127.0.0.1 %ld +%s :%s",
             uid, (long)now, nick, host, host, user, (long)now, modes, real);
}

/* Set oper status for a services pseudoclient */
static void inspircd_oper_mode(const char *source) {
    User *u = finduser(source);
    if (u) {
        send_cmd(ServerUID, "MODE %s +o", source);
    }
}

/* Send a SERVER message to introduce ourselves to the network. */
static void inspircd_server_connect(void) {
    /* Send our SERVER message - this is the first message sent */
    send_cmd(NULL, "SERVER %s %s 0 %s :%s", 
             ServerName, RemotePassword, ServerUID ? ServerUID : "100", ServerDesc);
    
    /* After the server connection, we need to negotiate the capabilities */
    inspircd_send_version();
    
    /* Set default modes for services */
    const char *svs_modes = InspIRCdUserModes ? InspIRCdUserModes : "io";
    
    /* Now introduce our services */
    inspircd_introduce_user(s_NickServ, ServiceUser, ServiceHost, "Nickname Service", svs_modes);
    inspircd_introduce_user(s_ChanServ, ServiceUser, ServiceHost, "Channel Service", svs_modes);
    inspircd_introduce_user(s_MemoServ, ServiceUser, ServiceHost, "Memo Service", svs_modes);
    inspircd_introduce_user(s_HelpServ, ServiceUser, ServiceHost, "Help Service", svs_modes);
    inspircd_introduce_user(s_OperServ, ServiceUser, ServiceHost, "Operator Service", svs_modes);
    inspircd_introduce_user(s_BotServ, ServiceUser, ServiceHost, "Bot Service", svs_modes);
    inspircd_introduce_user(s_CyberServ, ServiceUser, ServiceHost, "Cyber Service", svs_modes);
    inspircd_introduce_user(s_BddServ, ServiceUser, ServiceHost, "BDD Service", svs_modes);
    inspircd_introduce_user(RootNick, ServiceUser, ServiceHost, "Services Administrator", svs_modes);
    
    /* Set services as operators */
    inspircd_oper_mode(s_OperServ);
    inspircd_oper_mode(s_NickServ);
    inspircd_oper_mode(s_ChanServ);
    inspircd_oper_mode(RootNick);
}

/*************************************************************************/
/************************** NETWORK I/O FUNCTIONS ***********************/
/*************************************************************************/

/* Send a raw command to the IRC server. */
void inspircd_send_raw(const char *fmt, ...) {
    va_list args;
    char buf[BUFSIZE];
    
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    if (debug)
        log("debug: Sending: %s", buf);
    
    strncat(buf, "\r\n", sizeof(buf)-strlen(buf)-1);
    send(irc_sock, buf, strlen(buf), 0);
}

/* Send a command to the IRC server. */
void inspircd_send_cmd(const char *source, const char *fmt, ...) {
    va_list args;
    char buf[BUFSIZE];
    
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    if (source) {
        /* If source is a UID, use it, if it's a nickname, find its UID */
        if (is_valid_uid(source)) {
            send_raw(":%s %s", source, buf);
        } else {
            User *u = finduser(source);
            if (u && u->numerico) {
                send_raw(":%s %s", u->numerico, buf);
            } else {
                send_raw(":%s %s", source, buf);
            }
        }
    } else {
        send_raw(":%s %s", ServerUID ? ServerUID : "100", buf);
    }
}

/* Send a notice to a user */
void inspircd_notice_user(const char *source, const char *dest, const char *msg) {
    send_cmd(source, "NOTICE %s :%s", dest, msg);
}

/* Send a message to a channel */
void inspircd_notice_channel(const char *source, const char *dest, const char *msg) {
    send_cmd(source, "NOTICE %s :%s", dest, msg);
}

/* Send a private message to a user */
void inspircd_privmsg_user(const char *source, const char *dest, const char *msg) {
    send_cmd(source, "PRIVMSG %s :%s", dest, msg);
}

/* Set modes on a channel */
void inspircd_set_channel_mode(const char *source, const char *channel, const char *modes) {
    send_cmd(source, "MODE %s %s", channel, modes);
}

/* Join a channel */
void inspircd_join_channel(const char *source, const char *channel) {
    User *u = finduser(source);
    if (u) {
        send_cmd(source, "JOIN %s", channel);
    }
}

/*************************************************************************/
/************************* MESSAGE HANDLERS *****************************/
/*************************************************************************/

/* Parse NICK/UID message for InspIRCd 4
 * Format: UID <uid> <timestamp> <nick> <host> <dhost> <ident> <ip> <signon> +<modes> [<mode parameters>] :<realname>
 */
static int inspircd_process_nick(char *source, char *buf) {
    char *uid, *ts, *nick, *host, *dhost, *ident, *ip, *signon, *modes, *realname;
    User *user;
    
    if (strnicmp(buf, "UID ", 4) == 0) {
        /* Removing UID */
        buf += 4;
        
        uid = strtok(buf, " ");
        ts = strtok(NULL, " ");
        nick = strtok(NULL, " ");
        host = strtok(NULL, " ");
        dhost = strtok(NULL, " ");
        ident = strtok(NULL, " ");
        ip = strtok(NULL, " ");
        signon = strtok(NULL, " ");
        modes = strtok(NULL, " ");
        
        /* Get realname (starts with :) */
        realname = strtok(NULL, "");
        if (realname && *realname == ':')
            realname++;
        
        if (!uid || !ts || !nick || !host || !dhost || !ident || 
            !ip || !signon || !modes || !realname) {
            if (debug)
                log("%s: UID message: missing parameter(s)", s_OperServ);
            return 0;
        }
        
        /* Check if user already exists - shouldn't happen but worth checking */
        user = finduser(nick);
        if (user) {
            if (debug)
                log("%s: UID: nick %s already exists", s_OperServ, nick);
            return 0;
        }
        
        /* Create the user record */
        user = makeuser(nick);
        if (!user) {
            if (debug)
                log("%s: UID: unable to create user record for %s", s_OperServ, nick);
            return 0;
        }
        
        /* Fill in user fields */
        strscpy(user->username, ident, USERMAX);
        strscpy(user->host, dhost, HOSTMAX);
        strscpy(user->realname, realname, REALNAMEMAX);
        user->server = findserver(source);
        user->signon = atol(signon);
        user->my_signon = time(NULL);
        
        /* Store the UID in the numerico field */
#ifdef IRC_UNDERNET_P10
        user->numerico = strdup(uid);
#endif
        
        /* Set user modes */
        if (modes && *modes == '+')
            modes++;
        user->mode = parse_inspircd_user_modes(modes);
        
        /* Done */
        return 1;
    }
    
    return 0;
}

/* Main IRC protocol processing function - handle messages from the IRC server */
int inspircd_process(char *buf) {
    char *source, *cmd, *s;
    
    if (debug)
        log("debug: Received: %s", buf);
    
    /* Split the buffer into components */
    if (*buf == ':') {
        source = buf+1;
        s = strpbrk(source, " ");
        if (!s)
            return 0;
        *s++ = 0;
        while (*s == ' ')
            s++;
        if (!*s)
            return 0;
        buf = s;
    } else {
        source = NULL;
    }
    
    /* Get the command */
    if (strpbrk(buf, " ")) {
        cmd = strtok(buf, " ");
        s = strtok(NULL, "");
    } else {
        cmd = buf;
        s = "";
    }
    
    if (stricmp(cmd, "PING") == 0) {
        /* Handle PING specially because it's so common */
        if (*s == ':')
            s++;
        send_cmd(NULL, "PONG %s", s);
        
    } else if (stricmp(cmd, "UID") == 0) {
        /* New user connecting (handled in inspircd_process_nick) */
        return inspircd_process_nick(source, buf);
        
    } else if (stricmp(cmd, "QUIT") == 0) {
        /* User quitting */
        if (source)
            do_quit(source, s);
            
    } else if (stricmp(cmd, "SJOIN") == 0) {
        /* User joining a channel */
        /* Format: SJOIN <timestamp> <channel> <modes> [<mode parameters>] :[[@|+]<nick> [[@|+]<nick> ... ]] */
        char *ts, *chan, *modes, *nicks;
        
        ts = strtok(s, " ");
        chan = strtok(NULL, " ");
        modes = strtok(NULL, " ");
        
        /* Get the list of nicks - everything after : */
        nicks = strchr(s, ':');
        if (nicks)
            nicks++;
        
        if (ts && chan && modes && nicks) {
            /* Create the channel if it doesn't exist */
            Channel *c = findchan(chan);
            if (!c)
                c = makechan(chan);
            
            if (c) {
                c->creation_time = atol(ts);
                /* Process modes */
                c->mode = parse_inspircd_chan_modes(modes, c);
                
                /* Process user list */
                char *nick = strtok(nicks, " ");
                while (nick) {
                    char *flag = nick;
                    if (*flag == '@' || *flag == '+') {
                        nick++;
                    }
                    
                    User *u = finduser(nick);
                    if (u) {
                        /* Add user to channel */
                        add_user_to_channel(c, u);
                        
                        /* Handle flags */
                        if (*flag == '@') {
                            add_user_to_chanlist(u, c->chanops);
                        } else if (*flag == '+') {
                            add_user_to_chanlist(u, c->voices);
                        }
                    }
                    
                    nick = strtok(NULL, " ");
                }
            }
        }
        
    } else if (stricmp(cmd, "PART") == 0) {
        /* User leaving a channel */
        if (source) {
            char *chan = strtok(s, " ");
            User *u = finduser(source);
            Channel *c = findchan(chan);
            
            if (u && c) {
                remove_user_from_channel(c, u);
            }
        }
        
    } else if (stricmp(cmd, "MODE") == 0) {
        /* Mode change */
        char *target = strtok(s, " ");
        char *modes = strtok(NULL, "");
        
        if (target && modes) {
            if (*target == '#') {
                /* Channel mode change */
                Channel *c = findchan(target);
                if (c) {
                    c->mode = parse_inspircd_chan_modes(modes, c);
                }
            } else {
                /* User mode change */
                User *u = finduser(target);
                if (u) {
                    u->mode = parse_inspircd_user_modes(modes);
                }
            }
        }
        
    } else if (stricmp(cmd, "PRIVMSG") == 0 || stricmp(cmd, "NOTICE") == 0) {
        /* Message or notice */
        char *target = strtok(s, " ");
        char *message = strtok(NULL, "");
        
        if (target && message) {
            if (*message == ':')
                message++;
            
            /* Handle private messages to services */
            if (stricmp(cmd, "PRIVMSG") == 0 && *target != '#') {
                if (stricmp(target, s_NickServ) == 0) {
                    nickserv(source, message);
                } else if (stricmp(target, s_ChanServ) == 0) {
                    chanserv(source, message);
                } else if (stricmp(target, s_MemoServ) == 0) {
                    memoserv(source, message);
                } else if (stricmp(target, s_OperServ) == 0) {
                    operserv(source, message);
                } else if (stricmp(target, s_HelpServ) == 0) {
                    helpserv(source, message);
                } else if (stricmp(target, s_CyberServ) == 0) {
                    cyberserv(source, message);
                } else if (stricmp(target, s_BddServ) == 0) {
                    bddserv(source, message);
                } else if (stricmp(target, s_BotServ) == 0) {
                    botserv(source, message);
                } else if (stricmp(target, s_CregServ) == 0) {
                    cregserv(source, message);
                }
            }
        }
    }
    
    return 1;
}

/*************************************************************************/
/************************ PROTOCOL INITIALIZATION ************************/
/*************************************************************************/

/* Initialize protocol functions */
void init_protocol(void) {
    /* Set up local variables */
    ServerName = ServicesServerName;
    ServerDesc = ServicesServerDesc;
    ServerUID = ServerUID ? ServerUID : "100"; /* Default server numeric */
    
    s_NickServ = NS_NickName;
    s_ChanServ = CS_NickName;
    s_MemoServ = MS_NickName;
    s_HelpServ = HS_NickName;
    s_OperServ = OS_NickName;
    s_CyberServ = CY_NickName;
    s_BddServ = BD_NickName;
    s_CregServ = CR_NickName;
    s_BotServ = BS_NickName;
    ServiceHost = "services.local";
    RootNick = RootNickName;
    
    /* Set up protocol function pointers */
    server_connect = inspircd_server_connect;
    process = inspircd_process;
    send_cmd = inspircd_send_cmd;
    notice_user = inspircd_notice_user;
    notice_channel = inspircd_notice_channel;
    privmsg_user = inspircd_privmsg_user;
    set_channel_mode = inspircd_set_channel_mode;
    join_channel = inspircd_join_channel;
    
    if (debug)
        log("debug: InspIRCd 4 protocol module initialized");
}

#endif /* IRC_INSPIRCD_4 */