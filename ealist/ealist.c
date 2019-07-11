/*
    Copyright 2010 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

// gcc -o ealist ealist.c -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/ssl.h>    // link with libssl.a libcrypto.a -lgdi32
//#include "show_dump.h"

#ifdef WIN32
    #include <winsock.h>
    #include "winerr.h"

    #define close   closesocket
    #define sleep   Sleep
    #define ONESEC  1000
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>

    #define ONESEC  1
    #define stristr strcasestr
    #define stricmp strcasecmp
    #define strnicmp strncasecmp
#endif

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;



#define VER             "0.1.4"

#define SSL_COMPAT(X)   SSL_CTX_set_cipher_list(X, "ALL"); \
                        SSL_CTX_set_options(X, SSL_OP_ALL);
#define FILEOUT         "ealist-out.gsl"
#define DOITLATER_LIST  1
#define DOITLATER_UPD   2
#define DOITLATER_CFG   3
#define DOITLATER_CFG0  4
#define ARGHELP         !argv[i] || !strcmp(argv[i], "?") || !stricmp(argv[i], "help")
#define ARGHELP1        !argv[i] || !argv[i + 1] || !strcmp(argv[i + 1], "?") || !stricmp(argv[i + 1], "help")
#define CHECKARG(X)     i++; \
                        if(!argv[i]) { \
                            fprintf(stderr, "\n" \
                                "Error: " X \
                                "\n"); \
                            exit(1); \
                        }
#define FREEX(X)        freex((void *)&X)
void freex(void **buff) {
    if(!buff || !*buff) return;
    free(*buff);
    *buff = NULL;
}



int send_custom_func(SSL *ssl_sd, int sd, u32 type2);
u8 *fdloadx(u8 **fname, int *fsize);
u8 *fget_input(u8 *fmt, ...) ;
u8 *get_ea_value(u8 *data, int datalen, u8 *want_par);
int vspr(u8 **buff, u8 *fmt, va_list ap);
u8 *string_to_execute(u8 *str, u8 *ip, int port);
int mysend(SSL *ssl_sd, int sd, u8 *data, int datasz);
int myrecv(SSL *ssl_sd, int sd, u8 *data, int datasz);
void show_countries(void);
void show_filter_help(void);
void show_list(u8 *name);
void handle_server_info(u8 *data, int datalen, int show_server_info, u32 *ret_ip, u16 *ret_port);
void show_help(void);
void show_output_help(void);
u8 *ip2str(u32 ip);
int ea_send(SSL *ssl_sd, int sd, u8 *type1, u32 type2, u8 *fmt, ...);
u8 *ea_recv(SSL *ssl_sd, int sd, int *ret_len, u8 *type);
int recv_tcp(SSL *ssl_sd, int sd, u8 *data, int datalen);
int fake_fesl_server(int sd);
void myalloc(u8 **data, int wantsize, int *currsize);
int putxx(u8 *data, u32 num, int bytes);
u32 getxx(u8 *data, int bytes);
int timeout(int sock, int secs);
u32 resolv(char *host);
void std_err(void);



static const struct linger  lingerie = {1,1};
static const int    on = 1;
FILE    *fdout  = NULL;
int     quiet   = 0,
        verbose = 0,    // this is debugging, not a classical "verbose"
        dossl   = 1,
        fake_server_port = 0;
u16     msport  = 0;
u8      mshost[128] = "";

static int enctypex_data_cleaner_level = 2; // 0 = do nothing
                                            // 1 = colors
                                            // 2 = colors + strange chars
                                            // 3 = colors + strange chars + sql

u8      *send_custom_dest = NULL,
        *send_custom_type = NULL,
        *send_custom_file = NULL,
        *send_custom_data = NULL;



typedef struct {
    u16 port;
    u8  ssl;    // used only for possible future changes because ssl is used only for ports >= 18000
    u8  *name;
    u8  *description;
} games_list_t;
// note that the following could contain some errors, it's made by hand
// the replicated fields are corrects
static const games_list_t games_list[] = {  // "sort -k 4" do not use to avoid 17??? before 18???
    //{ 18300, 1, "159.153.234.11", "" },
    //{ 18560, 1, "159.153.235.19", "" },
    //{ 18310, 1, "159.153.234.20", "" },
    //{ 18510, 1, "159.153.234.26", "" },
    //{ 18570, 1, "159.153.234.27", "" },
    //{ 17540, 0, "159.153.234.32", "" },
    //{ 18540, 1, "159.153.234.32", "" },
    //{ 18550, 1, "159.153.234.32", "" },
    //{ 18570, 1, "159.153.235.12", "" },
    //{ 18570, 1, "159.153.235.14", "" },
    //{ 18570, 1, "159.153.235.20", "" },
    { 18330, 1, "ao2-360", "Age of Empires II (Xbox 360)" },
    { 17330, 0, "ao2-360", "Age of Empires II (Xbox 360)" },
    { 18490, 1, "ao2-demo-360", "Age of Empires II demo (Xbox 360)" },
    { 17490, 0, "ao2-demo-360", "Age of Empires II demo (Xbox 360)" },
    { 18340, 1, "ao2-ps3", "Age of Empires II (PS3)" },
    { 17070, 0, "ao2asia-360", "Age of Empires II asia (Xbox 360)" },
    { 18850, 1, "ao2asia-ps3", "Age of Empires II asia (PS3)" },
    { 17480, 0, "ao2eu-360", "Age of Empires II europe (Xbox 360)" },
    { 18131, 1, "ao3-360", "Age of Empires III (Xbox 360)" },
    { 17131, 0, "ao3-360", "Age of Empires III (Xbox 360)" },
    { 18520, 1, "ao3-closed-360", "Age of Empires III closed (Xbox 360)" },
    { 17520, 0, "ao3-closed-360", "Age of Empires III closed (Xbox 360)" },
    { 18530, 1, "ao3-closed-ps3", "Age of Empires III closed (PS3)" },
    { 18011, 1, "ao3-demo-360", "Age of Empires III demo (Xbox 360)" },
    { 17011, 0, "ao3-demo-360", "Age of Empires III demo (Xbox 360)" },
    { 18021, 1, "ao3-demo-ps3", "Age of Empires III demo (PS3)" },
    { 18991, 1, "ao3-jp-360", "Age of Empires III japan (Xbox 360)" },
    { 17991, 0, "ao3-jp-360", "Age of Empires III japan (Xbox 360)" },
    { 18981, 1, "ao3-jp-ps3", "Age of Empires III japan (PS3)" },
    { 18141, 1, "ao3-ps3", "Age of Empires III (PS3)" },
    { 18341, 1, "beach-360-server", "Beach (Xbox 360 server)" },
    { 17341, 0, "beach-360-server", "Beach (Xbox 360 server)" },
    { 18241, 1, "beach-360", "Beach (Xbox 360)" },
    { 17241, 0, "beach-360", "Beach (Xbox 360)" },
    { 18331, 1, "beach-ps3-server", "Beach (PS3 server)" },
    { 18231, 1, "beach-ps3", "Beach (PS3)" },
    { 18300, 1, "bf2142-pc", "Battlefield 2142" },
    { 18280, 1, "bfbc-360", "Battlefield: Bad Company (Xbox 360)" },
    { 17280, 0, "bfbc-360", "Battlefield: Bad Company (Xbox 360)" },
    { 18800, 1, "bfbc-ps3", "Battlefield: Bad Company (PS3)" },
    { 18341, 1, "bfbc2-360-server", "Battlefield: Bad Company 2 (Xbox 360 server)" },
    { 18111, 1, "bfbc2-360", "Battlefield: Bad Company 2 (Xbox 360)" },
    { 17111, 0, "bfbc2-360", "Battlefield: Bad Company 2 (Xbox 360)" },
    { 18321, 1, "bfbc2-pc-server", "Battlefield: Bad Company 2 (server)" },
    { 18390, 1, "bfbc2-pc", "Battlefield: Bad Company 2" },
    { 18331, 1, "bfbc2-ps3-server", "Battlefield: Bad Company 2 (PS3 server)" },
    { 18121, 1, "bfbc2-ps3", "Battlefield: Bad Company 2 (PS3)" },
    { 17110, 0, "bfmc", "Battlefield: Modern Combat" },
    { 17190, 0, "bfmc-360", "Battlefield: Modern Combat (Xbox 360)" },
    { 17150, 0, "bfmc-360-demo", "Battlefield: Modern Combat demo (Xbox 360)" },
    // bfme2.fesl.ea.com on port 18160 doesn't work (with and without ssl)
    { 17180, 0, "bfme2-360", "Lord of the Rings The Battle for Middle-earth 2 (Xbox 360)" },
    { 17170, 0, "bfme2-360", "Lord of the Rings The Battle for Middle-earth 2 (Xbox 360 alpha)" },
    { 18270, 1, "bfwest-dedicated", "Battlefield Heroes" },
    { 18051, 1, "bfwest-server", "Battlefield Heroes (server)" },
    { 18460, 1, "cnc3-360", "Command & Conquer 3 (Xbox 360)" },
    { 17460, 0, "cnc3-360", "Command & Conquer 3 (Xbox 360)" },
    { 17610, 0, "cnc3-360-demo", "Command & Conquer 3 demo (Xbox 360)" },
    { 18750, 1, "cnc3-ep1-360", "Command & Conquer 3 ep1 (Xbox 360)" },
    { 17750, 0, "cnc3-ep1-360", "Command & Conquer 3 ep1 (Xbox 360)" },
    { 18760, 1, "cnc3-ep1-pc", "Command & Conquer 3 ep1" },
    { 18840, 1, "cncra3-pc", "Command & Conquer 3: Red Alert (PC)" },
    { 17830, 0, "cncra3-360", "Command & Conquer 3: Red Alert (Xbox 360)" },
    { 18290, 1, "cncra3-ps3", "Command & Conquer 3: Red Alert (PS3)" },
    //{ 18120, 1, "core", "core (bf2?), no longer exists"},
    { 18100, 1, "dragonage-360", "Dragon Age: Origins (Xbox 360)" },
    { 17100, 0, "dragonage-360", "Dragon Age: Origins (Xbox 360)" },
    { 18081, 1, "dragonage-pc", "Dragon Age: Origins" },
    { 18101, 1, "dragonage-ps3", "Dragon Age: Origins (PS3)" },
    { 18090, 1, "fifamanager-pc", "FIFA Manager" },
    { 18320, 1, "godfather-360", "Godfather (Xbox 360)" },
    { 17320, 0, "godfather-360", "Godfather (Xbox 360 test)" },
    { 18020, 1, "godfather2-360", "Godfather 2 (Xbox 360)" },
    { 17020, 0, "godfather2-360", "Godfather 2 (Xbox 360)" },
    { 18080, 1, "godfather2-pc", "Godfather 2" },
    { 18450, 1, "hl2-ps3", "Half-Life 2 (PS3)" },
    { 18251, 1, "lotr-pandemic-360", "Lord of the Rings Conquest (Xbox 360)" },
    { 18860, 1, "lotr-pandemic-360", "Lord of the Rings Conquest (Xbox 360)" },
    { 17860, 0, "lotr-pandemic-360", "Lord of the Rings Conquest (Xbox 360)" },
    { 17251, 0, "lotr-pandemic-demo-360", "Lord of the Rings Conquest demo (Xbox 360)" },
    { 18880, 1, "lotr-pandemic-pc", "Lord of the Rings Conquest" },
    { 18271, 1, "lotr-pandemic-ps3", "Lord of the Rings Conquest (PS3)" },
    { 18870, 1, "lotr-pandemic-ps3", "Lord of the Rings Conquest (PS3)" },
    { 18630, 1, "mercs2-360", "Mercenaries 2 (Xbox 360)" },
    { 17630, 0, "mercs2-360", "Mercenaries 2 (Xbox 360)" },
    { 18710, 1, "mercs2-pc", "Mercenaries 2" },
    { 18720, 1, "mercs2-ps3", "Mercenaries 2 (PS3)" },
    { 18250, 1, "mohair-360", "Medal of Honor: Airborne (Xbox 360)" },
    { 17250, 0, "mohair-360", "Medal of Honor: Airborne (Xbox 360)" },
    { 18240, 1, "mohair-pc", "Medal of Honor: Airborne" },
    { 18260, 1, "mohair-ps3", "Medal of Honor: Airborne (PS3)" },
    { 18130, 1, "mysims-pc", "MySims" },
    { 17220, 0, "nfs-360", "Need for Speed (Xbox 360)" },
    { 18210, 1, "nfs-pc", "Need for Speed" },
    { 18230, 1, "nfs-ps3", "Need for Speed (PS3)" },
    { 18920, 1, "nfsmw2-360", "Need for Speed Most Wanted 2 (Xbox 360)" },
    { 17920, 0, "nfsmw2-360", "Need for Speed Most Wanted 2 (Xbox 360)" },
    { 18940, 1, "nfsmw2-pc", "Need for Speed Most Wanted 2" },
    { 18930, 1, "nfsmw2-ps3", "Need for Speed Most Wanted 2 (PS3)" },
    { 18590, 1, "nfsps-360", "Need for Speed Pro Street (Xbox 360)" },
    { 17590, 0, "nfsps-360", "Need for Speed Pro Street (Xbox 360)" },
    { 18580, 1, "nfsps-pc", "Need for Speed Pro Street" },
    { 18600, 1, "nfsps-ps3", "Need for Speed Pro Street (PS3)" },
    { 18211, 1, "nfsps2-360", "Need for Speed Pro Street 2 (Xbox 360)" },
    { 17211, 0, "nfsps2-360", "Need for Speed Pro Street 2 (Xbox 360)" },
    { 17311, 0, "nfsps2-360", "Need for Speed Pro Street 2 (Xbox 360)" },
    { 18311, 1, "nfsps2-360", "Need for Speed Pro Street 2 (Xbox 360)" },
    { 18201, 1, "nfsps2-pc", "Need for Speed Pro Street 2" },
    { 18301, 1, "nfsps2-pc", "Need for Speed Pro Street 2" },
    { 18221, 1, "nfsps2-ps3", "Need for Speed Pro Street 2 (PS3)" },
    { 18321, 1, "nfsps2-ps3", "Need for Speed Pro Street 2 (PS3)" },
    { 18360, 1, "qa", "EA Quality Assurance (game testers)" },
    { 18410, 1, "skate-360", "EA SKate (Xbox 360)" },
    { 17410, 0, "skate-360", "EA SKate (Xbox 360)" },
    { 18420, 1, "skate-ps3", "EA SKate (PS3)" },
    { 18820, 1, "skate2-360", "EA SKate 2 (Xbox 360)" },
    { 17820, 0, "skate2-360", "EA SKate 2 (Xbox 360)" },
    { 18040, 1, "skate2-ps3", "EA SKate 2 (PS3)" },
    { 18191, 1, "takedown-demo-pc", "" },
    { 17690, 0, "takedown-360", "" },
    { 0,     0, NULL, NULL }
};



int main(int argc, char *argv[]) {
    SSL_CTX     *ctx_sd     = NULL;
    //SSL_METHOD  *ssl_method = NULL;
    SSL         *ssl_sd     = NULL;
    struct  sockaddr_in peer;
    u32     ip;
    int     i,
            j,
            len,
            sd               = 0,
            fesl_sd          = 0,
            servers          = 0,
            show_server_info = 0,
            iwannaloop       = 0,
            doitlater_type   = 0,
            tid              = 0,
            sku              = 125170,  // doesn't matter
            lid              = 0,
            num_lobbies      = 0,
            num_games        = 0,
            theater_only     = 0,
            create_account   = 0,
            *lobbies         = NULL;
    u16     port             = 0,
            theater_port     = 0;
    u8      theater_host[128]= "",
            macaddr[64],
            type[4],
            outtype          = 0,
            *tmpexec         = NULL,
            *execstring      = NULL,
            *doitlater_str   = NULL,
            *multigamename   = NULL,
            *multigamenamep  = NULL,
            *gamestr         = NULL,
            //*filter          = NULL,
            *fname           = NULL,
            *buff            = NULL,
            *data            = NULL,
            *account_user    = NULL,
            *account_pass    = NULL,
            *account_game    = NULL,
            *account_mail    = NULL,
            *lkey            = NULL,
            *ipc,
            *p;

#ifdef WIN32
    WSADATA    wsadata;
    WSAStartup(MAKEWORD(1,0), &wsadata);
#endif

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    fputs("\n"
        "EAlist "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stderr);

    fdout = stdout;

    if(argc < 2) {
        show_help();
        exit(1);
    }

    for(i = 1; i < argc; i++) {
        if(stristr(argv[i], "--help")) {
            show_help();
            return(0);
        }
        if(((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) {
            fprintf(stderr, "\n"
                "Error: recheck your options (%s is not valid)\n"
                "\n", argv[i]);
            exit(1);
        }

        switch(argv[i][1]) {
            case '-':
            case '/':
            case '?':
            case 'h': {
                show_help();
                return(0);
                } break;
            case 'a': {
                CHECKARG("you must specify the account's username\n")
                account_user = argv[i];
                CHECKARG("you must specify the account's password\n")
                account_pass = argv[i];
                CHECKARG("you must specify the account's gamename (where your account is enabled)\n")
                account_game = argv[i];
                } break;
            case 'A': {
                create_account = 1;
                } break;
            case 'n':
            case 'N': {
                CHECKARG("you must select a gamename\n"
                    "       Use -l for the full list or -s for searching a specific game\n")
                gamestr = argv[i];
                } break;
            case 'l': {
                doitlater_type = DOITLATER_LIST;
                } break;
            case 's': {
                CHECKARG("you must specify a text pattern to search in the game database\n")
                doitlater_type = DOITLATER_LIST;
                doitlater_str  = argv[i];
                } break;
            /*case 'f': {
                i++;
                if(ARGHELP) {
                    show_filter_help();
                    return(0);
                }
                filter = argv[i];
                } break;*/
            case 'r': {
                CHECKARG("you missed to pass the parameter to the option\n")
                execstring = argv[i];
                } break;
            case 'o': {
                i++;
                if(ARGHELP) {
                    show_output_help();
                    return(0);
                }
                outtype = atoi(argv[i]);
                if(outtype > 6) outtype = 0;
                if(!outtype) {
                    fdout = fopen(argv[i], "wb");
                    if(!fdout) std_err();
                }
                } break;
            case 'q': {
                quiet = 1;
                } break;
            case 'x': {
                CHECKARG("you must specify the master server and optionally its port\n")
                p = strchr(argv[i], ':');
                if(p) {
                    msport = atoi(p + 1);
                    *p++ = 0;
                    p = strchr(p, ':'); // for ssl
                    if(p) {
                        *p++ = 0;
                        dossl = atoi(p);
                    }
                }
                strncpy(mshost, argv[i], sizeof(mshost));
                //mymshost = mshost;
                } break;
            case 'L': {
                CHECKARG("you must specify the amount of seconds for the loop\n")
                iwannaloop = atoi(argv[i]);
                } break;
            /*case 'c': {
                show_countries();
                return(0);
                } break;*/
            //case 'u':
            //case 'U': {
                //doitlater_type = DOITLATER_UPD;
                //} break;
            case 'X': {
                CHECKARG("you must specify the informations you want to return from enctypex\n"
                    "       for example: -t -1 -X \\hostname\\gamever\\gametype\\gamemode\\numplayers\n")
                show_server_info = 1;
                } break;
            case 'C': {
                enctypex_data_cleaner_level = 0;
                } break;
            case 'v': {
                verbose = 1;
                } break;
            case 'V': {
                theater_only = 1;
                } break;
            case 'F': {
                send_custom_dest = argv[++i];
                send_custom_type = argv[++i];
                send_custom_file = argv[++i];
                verbose = 1;    // enabled by default
                } break;
            case 'S': {
                CHECKARG("you must specify the port to bind\n")
                p = argv[i];
                fake_server_port = atoi(p);
                p = strchr(p, ':'); // for ssl
                if(p) dossl = atoi(p + 1);
                } break;
            default: {
                fprintf(stderr, "\n"
                    "Error: wrong argument (%s)\n"
                    "\n", argv[i]);
                exit(1);
                } break;
        }
    }

    srand(time(NULL));

    if(doitlater_type) {
        switch(doitlater_type) {
            case DOITLATER_LIST:    show_list(doitlater_str);   break;
            case DOITLATER_UPD:     gamestr = "";               break;
            default: break;
        }
        if(doitlater_type != DOITLATER_UPD) return(0);  // temporary (debug only)
    }

    SSL_library_init();
    SSL_load_error_strings();

    if(fake_server_port > 0) {
        peer.sin_addr.s_addr = htonl(INADDR_ANY);
        peer.sin_port        = htons(fake_server_port);
        peer.sin_family      = AF_INET;

        fesl_sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(fesl_sd < 0) std_err();
        if(setsockopt(fesl_sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on))
          < 0) std_err();
        if(bind(fesl_sd, (struct sockaddr *)&peer, sizeof(struct sockaddr_in))
          < 0) std_err();
        if(listen(fesl_sd, SOMAXCONN)
          < 0) std_err();

        fprintf(stderr, "- fake fesl server listening on port %hu (one client at time only!)\n", ntohs(peer.sin_port));

        for(;;) {
            len = sizeof(struct sockaddr_in);
            sd = accept(fesl_sd, (struct sockaddr *)&peer, &len);
            if(sd < 0) std_err();
            setsockopt(sd, SOL_SOCKET, SO_LINGER, (char *)&lingerie, sizeof(lingerie));

            fprintf(stderr, "%s : %hu\n",
                inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

            fake_fesl_server(sd);
        }
        close(fesl_sd);
        return(0);
    }

    //ea_filter(&list_opt, filter);

    if(!account_user || !account_pass || !account_game) {
        if(create_account) {
            if(!account_user) account_user = fget_input("- insert the username of the EA account to create:\n  ");
            if(!account_pass) account_pass = fget_input("- insert the password of the EA account to create:\n  ");
            if(!account_game) {
                if(gamestr) account_game = gamestr;
                account_game = fget_input("- insert the gamename of the EA account to create (if in doubt use mohair-pc):\n  ");
                if(!account_game[0]) account_game = "mohair-pc";
            }
        } else {
            fprintf(stderr, "\n"
                "Error: you must add the option -a USER PASS GAME for using this tool.\n"
                "       example: -a myusername mypassword bfbc2-pc\n"
                "       example: -a myusername mypassword \"\" (it will use the same of -n)\n"
                "\n"
                "       this is necessary because various games use a \"per-game\" account, in\n"
                "       short although the account is unique and valid for any EA game in some\n"
                "       cases it's necessary to \"activate\" it for a specific one.\n"
                "       that's why I have added the GAME parameter that should allow to get the\n"
                "       servers list of other games using a cross-query\n"
                "       anyway don't worry because will be displayed the verbose error message\n"
                "       reported by the server in case of problems.\n"
                "       if you have doubts or something is not clear contact me\n"
                "\n");
            exit(1);
        }
    }
    if(create_account) {
        gamestr = account_game; // in case -n was not used
        if(!account_mail) account_mail = fget_input("- insert the e-mail of the EA account to create:\n  (any address is ok because EA doesn't require confirmations)\n  ");
    }
    if(!gamestr) {
        fprintf(stderr, "\n"
            "Error: The game is not available or has not been specified.\n"
            "       Use -n to specify a gamename, example: -n bfbc2-pc\n"
            "\n");
        exit(1);
    }
    if(!account_game[0]) account_game = gamestr;

    /* quick explanation:
    - connect to fesl for authenticating (retrieving slkey) and for retrieving the theater server
    - connect to the theater for retrieving the servers list
    if you already have the slkey there is no problem in contacting the theater server directly
    except that you must know it's host and port and at the moment is not possible to specify it
    in this tool, that's why also the "multigamename" function is disabled
    */

    //if(!fesl_sd) {
        if(!mshost[0]) {
            snprintf(mshost, sizeof(mshost), "%s.fesl.ea.com", gamestr);
        }
        if(!msport) {
            for(i = 0; games_list[i].name; i++) {
                if(!stricmp(games_list[i].name, gamestr)) {
                    msport = games_list[i].port;
                    dossl  = games_list[i].ssl;
                    break;
                }
            }
            if(!msport) {
                fprintf(stderr, "\n"
                    "Error: you have specified a gamename that is not available in the list of this\n"
                    "       tool, indeed is necessary to know the exact fesl port for the specific\n"
                    "       game for performing the login correctly.\n"
                    "       anyway contact me if you know one or more games not included here yet.\n"
                    "       use the -l option for the list of supported games currently listed.\n"
                    "\n");
                exit(1);
            }
        }

        peer.sin_addr.s_addr = resolv(mshost);
        peer.sin_port        = htons(msport);
        peer.sin_family      = AF_INET;

        fprintf(stderr, "- target   %s : %hu\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

        fesl_sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(fesl_sd < 0) std_err();
        if(connect(fesl_sd, (struct sockaddr *)&peer, sizeof(peer))
          < 0) std_err();
        if(dossl) {
            ctx_sd = SSL_CTX_new(SSLv3_method());
            SSL_COMPAT(ctx_sd)
            ssl_sd = SSL_new(ctx_sd);
            SSL_set_fd(ssl_sd, fesl_sd);
            if(SSL_connect(ssl_sd) < 0) goto quit;
        } else {
            ssl_sd = NULL;
        }
    //}
    sprintf(macaddr, "%04x%04x%04x", rand(), rand(), rand());

    multigamename = gamestr;

get_list:
    multigamenamep = strchr(gamestr, ',');
    if(multigamenamep) {
        fprintf(stderr, "\nError: at the moment this tool doesn't support the querying of multiple gamenames\n");
        exit(1);
        *multigamenamep = 0;
    }
    if(!quiet) fprintf(stderr, "Gamename:    %s\n", gamestr);

    switch(outtype) {
        case 0: break;
        case 1:
        case 3: {
            if(!fname) fname = malloc(strlen(gamestr) + 10);
            sprintf(fname, "%s.gsl", gamestr);
            } break;
        case 2:
        case 4: {
            if(!fname) fname = malloc(strlen(FILEOUT) + 10);
            sprintf(fname, "%s",     FILEOUT);
            } break;
        case 5:
        case 6: {
            fdout = stdout;
            } break;
        default: break;
    }

    if(fname) {
        if(!quiet) fprintf(stderr, "- output file: %s\n", fname);
        fdout = fopen(fname, "wb");
        if(!fdout) std_err();
        FREEX(fname);
    }


    /***************/
    /* feal.ea.com */
    /***************/

    if(fesl_sd) {   // try to make it only one time
        if(ea_send(ssl_sd, fesl_sd, "fsys", 0xc0000001,
            "TXN=Hello\n"
            "clientString=%s\n"
            "sku=%d\n"
            "locale=en_US\n"
            "clientPlatform=PC\n"
            "clientVersion=1.18.207823.0\n"
            "SDKVersion=5.0.0.0.0\n"
            "protocolVersion=2.0\n"
            "fragmentSize=8096\n"
            "clientType=client\n",  // client-noreg
            account_game,   // allows the cross-queries, otherwise use gamestr
            sku) < 0) goto quit;
        buff = ea_recv(ssl_sd, fesl_sd, &len, NULL);
        if(!buff || (len < 0)) goto quit;

        p = get_ea_value(buff, len, "theaterIp");
        if(!p) {
            fprintf(stderr, "\nError: no theaterIp, dump follows:\n---\n%.*s\n---\n", len, buff);
            exit(1);
        }
        strncpy(theater_host, p, sizeof(theater_host));
        p = get_ea_value(buff, len, "theaterPort");
        if(!p) {
            fprintf(stderr, "\nError: no theaterPort, dump follows:\n---\n%.*s\n---\n", len, buff);
            exit(1);
        }
        theater_port = atoi(p);
        if(!quiet) fprintf(stderr, "theater:     %s : %hu\n", theater_host, theater_port);

        if(theater_only) exit(0);

        buff = ea_recv(ssl_sd, fesl_sd, &len, NULL); // MemCheck
        if(!buff || (len < 0)) goto quit;
        p = get_ea_value(buff, len, "TXN");
        if(p && !stricmp(p, "MemCheck")) {
            if(ea_send(ssl_sd, fesl_sd, "fsys", 0x80000000,
                "TXN=MemCheck\n"
                "result=\n") < 0) goto quit;
        }

        if(create_account) {
            if(ea_send(ssl_sd, fesl_sd, "acct", 0xc0000002, // useless, only to match a normal client at 100%
                "TXN=GetCountryList\n") < 0) goto quit;
            do {
                buff = ea_recv(ssl_sd, fesl_sd, &len, NULL);
                if(!buff || (len < 0)) goto quit;

            } while(len >= 8096);

            if(ea_send(ssl_sd, fesl_sd, "acct", 0xc0000003, // useless, only to match a normal client at 100%
                "TXN=GetTos\n") < 0) goto quit;
            do {
                buff = ea_recv(ssl_sd, fesl_sd, &len, NULL);
                if(!buff || (len < 0)) goto quit;
            } while(len >= 8096);

            if(ea_send(ssl_sd, fesl_sd, "acct", 0xc0000004,
                "TXN=AddAccount\n"
                "name=%s\n"
                "password=%s\n"
                "email=%s\n"
                "DOBDay=1\n"
                "DOBMonth=1\n"
                "DOBYear=1980\n"
                "zipCode=90094\n"
                "countryCode=US\n"
                "parentalEmail=parents@ea.com\n"
                "eaMailFlag=0\n"
                "thirdPartyMailFlag=0\n",
                account_user,
                account_pass,
                account_mail) < 0) goto quit;
            for(;;) {
                buff = ea_recv(ssl_sd, fesl_sd, &len, NULL);
                if(!buff || (len < 0)) goto quit;
                p = get_ea_value(buff, len, "TXN");
                if(p && !stricmp(p, "AddAccount")) break;
            }

            fprintf(stderr, "- the account should have been created correctly\n");

            if(dossl) {
                if(ssl_sd) {
                    SSL_shutdown(ssl_sd);
                    SSL_free(ssl_sd);
                }
                if(ctx_sd) SSL_CTX_free(ctx_sd);
            }
            close(fesl_sd);
            fesl_sd = 0;

            fprintf(stderr, "- done\n");
            exit(0);
        }

        // the following info is totally useless for this tool, but could be interesting:
        // in Battlefield Heroes it's used a particular method for the login:
        // instead of using name and password (clear-text or encrypted) it uses
        // the encryptedInfo field containing a code received from an HTTP request
        // to bfhweb32.eao.abn-iad.ea.com (aka www.battlefieldheroes.com) like:
        //   GET /nucleus/authToken HTTP/1.1
        //   Cookie: magma=**************************
        //   User-Agent: BFHeroesINet
        //   Host: www.battlefieldheroes.com
        //   Connection: Keep-Alive
        //   Cache-Control: no-cache
        //   Pragma: no-cache
        // where magma is followed by the same sessionId string used to launch BFHeroes.exe
        // (open Process Explorer and check the command-line of the process, the sessionId is visible there)

        if(ea_send(ssl_sd, fesl_sd, "acct", 0xc0000002,
            "TXN=Login\n"   // BFHeroes uses NuLogin
            "returnEncryptedInfo=0\n"
            "name=%s\n"     // alternatively some games use encryptedInfo
            "password=%s\n" // instead of the clear-text name and password
            "macAddr=$%s\n",
            account_user,
            account_pass,
            macaddr) < 0) goto quit;
        buff = ea_recv(ssl_sd, fesl_sd, &len, NULL);
        if(!buff || (len < 0)) goto quit;

        p = get_ea_value(buff, len, "lkey");    // fesl is necessary mainly only for this parameter
        if(!p) {
            fprintf(stderr, "\nError: no lkey, dump follows:\n---\n%.*s\n---\n", len, buff);
            exit(1);
        }
        lkey = strdup(p);
        if(!quiet) fprintf(stderr, "lkey:        %s\n", lkey);

        if(send_custom_dest && (tolower(send_custom_dest[0]) == 'f')) { // fesl
            if(send_custom_func(ssl_sd, fesl_sd, 0xc0000003) < 0)goto quit;
        }

        if(ea_send(ssl_sd, fesl_sd, "fsys", 0xc0000003,  // logout
            "TXN=Goodbye\n"
            "reason=GOODBYE_CLIENT_NORMAL\n"
            "message=\"Disconnected via front-end\"\n") < 0) goto quit;
        if(dossl) {
            if(ssl_sd) {
                SSL_shutdown(ssl_sd);
                SSL_free(ssl_sd);
            }
            if(ctx_sd) SSL_CTX_free(ctx_sd);
        }
        close(fesl_sd);
        fesl_sd = 0;
    }


    /******************/
    /* theater.ea.com */
    /******************/

    if(!sd) {   // reuse the connection if it's still up
        peer.sin_addr.s_addr = resolv(theater_host);
        peer.sin_port        = htons(theater_port);
        peer.sin_family      = AF_INET;

        sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(sd < 0) std_err();
        if(connect(sd, (struct sockaddr *)&peer, sizeof(peer))
          < 0) std_err();

        tid = 0;

        if(ea_send(NULL, sd, "CONN", 0x40000000,
            "PROT=2\n"
            "PROD=%s\n"
            "VERS=1.1\n"
            "PLAT=PC\n"
            "LOCALE=en_US\n"
            "SDKVERSION=5.0.0.0.0\n"
            "TID=%d\n",
            gamestr,
            ++tid) < 0) goto quit;
        buff = ea_recv(NULL, sd, &len, NULL);
        if(!buff || (len < 0)) goto quit;

        if(ea_send(NULL, sd, "USER", 0x40000000,
            "MAC=$%s\n"
            "SKU=%d\n"
            "LKEY=%s\n"
            "NAME=\n"
            "TID=%d\n",
            macaddr,
            sku,
            lkey,
            ++tid) < 0) goto quit;
        buff = ea_recv(NULL, sd, &len, NULL);
        if(!buff || (len < 0)) goto quit;
    }

    if(send_custom_dest && (tolower(send_custom_dest[0]) == 't')) { // theater
        if(send_custom_func(NULL, sd, 0x40000000) < 0)goto quit;
    }

    if(ea_send(NULL, sd, "LLST", 0x40000000,
        "FILTER-FAV-ONLY=0\n"
        "FILTER-NOT-FULL=0\n"
        "FILTER-NOT-PRIVATE=0\n"
        "FILTER-NOT-CLOSED=0\n"
        "FILTER-MIN-SIZE=0\n"
        "FAV-PLAYER=\n"
        "FAV-GAME=\n"
        "FAV-PLAYER-UID=\n"
        "FAV-GAME-UID=\n"
        "TID=%d\n",
        ++tid) < 0) goto quit;
    buff = ea_recv(NULL, sd, &len, NULL);   // LLST
    if(!buff || (len < 0)) goto quit;

    p = get_ea_value(buff, len, "num-lobbies");
    num_lobbies = p ? atoi(p) : 1;  // one lobby?
    lobbies = calloc(num_lobbies, sizeof(lid));
    if(!lobbies) std_err();

    for(j = 0; j < num_lobbies; j++) {
        buff = ea_recv(NULL, sd, &len, NULL);   // LDAT
        if(!buff || (len < 0)) goto quit;
        p = get_ea_value(buff, len, "lid");
        lobbies[j] = p ? atoi(p) : 0;
    }

    /* the following is not necessary
    if(ea_send(NULL, sd, "PCNT", 0x40000000,
        "LID=%d\n"
        "TID=%d\n",
        lid,
        ++tid) < 0) goto quit;
    buff = ea_recv(NULL, sd, &len, NULL);
    if(!buff || (len < 0)) goto quit;
    */

    servers = 0;
    for(j = 0; j < num_lobbies; j++) {
        lid = lobbies[j];

        if(ea_send(NULL, sd, "GLST", 0x40000000,
            "LID=%d\n"
            "TYPE=\n"       // TYPE=G
            "FILTER-FAV-ONLY=0\n"
            "FILTER-NOT-FULL=0\n"
            "FILTER-NOT-PRIVATE=0\n"
            "FILTER-NOT-CLOSED=0\n" // was 1
            "FILTER-MIN-SIZE=0\n"
            "FAV-PLAYER=\n"
            "FAV-GAME=\n"
            "COUNT=-1\n"
            "FAV-PLAYER-UID=\n"
            "FAV-GAME-UID=\n"
            "TID=%d\n",
            lid,
            ++tid) < 0) goto quit;
        do {
            buff = ea_recv(NULL, sd, &len, type);   // GLST
            if(!buff || (len < 0)) goto quit;
        } while(memcmp(type, "GLST", 4));

        p = get_ea_value(buff, len, "num-games");
        num_games = p ? atoi(p) : 0;

        if(!quiet) {
            fprintf(stderr,
                "Receiving:   %d servers from %d\n"
                "-----------------------\n",
                num_games, lid);
        }

        /*
        if(outtype == 6) {
            fprintf(stderr, "\n\n");
            show_dump(buff, len, fdout);
            fputc('\n', stderr);
            //goto ealist_exit;
            outtype = 0;
        }

        if(doitlater_type == DOITLATER_UPD) {
            fprintf(stderr, "\n- update not yet implemented (only for debug), hex dump follows:\n");
            show_dump(data, datalen, stdout);
            exit(1);
        }
        */

//handle_servers:
        for(i = 0; i < num_games; i++) {
            buff = ea_recv(NULL, sd, &len, NULL);   // GDAT
            if(!buff || (len < 0)) goto quit;
            handle_server_info(buff, len, show_server_info, &ip, &port);

            ipc = ip2str(ip);
            if(!show_server_info) {
                switch(outtype) {
                    case 0: {
                        fprintf(fdout, "%15s   %hu\n", ipc, port);
                        } break;
                    case 5:
                    case 1:
                    case 2: {
                        fprintf(fdout, "%s:%hu\n", ipc, port);
                        } break;
                    case 3:
                    case 4: {
                        fwrite((u8 *)&ip, 1, 4, fdout);
                        fputc((port >> 8) & 0xff, fdout);
                        fputc(port & 0xff, fdout);
                        } break;
                    default: break;
                }
            }

            if(execstring) {
                tmpexec = string_to_execute(execstring, ipc, port);
                fprintf(stderr, "   Execute: \"%s\"\n", tmpexec);
                system(tmpexec);
                free(tmpexec);
            }
        }
        servers += i;
    }
    FREEX(lobbies);

    if(!quiet) fprintf(stderr, "\n%u servers found\n\n", servers);

    fflush(fdout);
    if(outtype) fclose(fdout);
        // -o filename will be closed when the program is terminated

    if(multigamenamep) {
        *multigamenamep = ',';
        gamestr = multigamenamep + 1;
        goto get_list;
    } else {
        gamestr = multigamename;
    }

    if(iwannaloop) {
        close(sd);  // better to close it
        sd = 0;

        for(i = 0; i < iwannaloop; i++) {
            sleep(ONESEC);
        }
        goto get_list;
    }

//ealist_exit:
    if(sd) close(sd);
    FREEX(tmpexec);
    FREEX(buff);
    FREEX(data);
    return(0);
quit:
    fprintf(stderr, "\nError: there has been an error during the connection with the server\n");
    exit(1);
}



int send_custom_func(SSL *ssl_sd, int sd, u32 type2) {
    int     len;
    u8      *buff,
            *p;

    fprintf(stderr, "\n- start the sending of custom data and the receiving loop:\n");
    for(;;) {
        send_custom_data = fdloadx(&send_custom_file, NULL);
        if(!send_custom_data) break;
        p = strchr(send_custom_type, ',');
        if(!p) p = strchr(send_custom_type, ';');
        if(p) *p = 0;
        if(ea_send(ssl_sd, sd, send_custom_type, type2,
            "%s",
            send_custom_data) < 0) goto quit;
        free(send_custom_data);
        if(p) send_custom_type = p + 1;
        buff = ea_recv(ssl_sd, sd, &len, NULL);    // seems necessary
        if(!buff || (len < 0)) goto quit;
    }
    for(;;) {   // yeah, endless recv
        buff = ea_recv(ssl_sd, sd, &len, NULL);
        if(!buff || (len < 0)) goto quit;
    }
    return(0);
quit:   // for copy&paste compatibility
    return(-1);
}



u8 *fdloadx(u8 **fname, int *fsize) {
    struct stat xstat;
    FILE    *fd;
    int     size,
            i,
            c;
    u8      *buff,
            *p;

    if(!fname || !fname[0]) return(NULL);
    p = strchr(*fname, ',');
    if(!p) p = strchr(*fname, ';');
    if(p) *p = 0;
    fprintf(stderr, "- load data from file %s\n", *fname);
    fd = fopen(*fname, "rb");
    if(!fd) std_err();
    if(p) {
        *fname = p + 1;
    } else {
        *fname = NULL;
    }

    fstat(fileno(fd), &xstat);
    size = xstat.st_size;
    buff = malloc(size + 1);
    if(!buff) std_err();
    //fread(buff, 1, size, fd);
    for(i = 0; i < size;) {
        c = fgetc(fd);
        if(c < 0) break;
        if(c == '\r') continue; // the EA servers do NOT want \r
        buff[i] = c;
        i++;
    }
    buff[i] = 0; // needed to have a delimiter
    size = i;

    fclose(fd);
    if(fsize) *fsize = size;
    return(buff);
}



u8 *fget_input(u8 *fmt, ...) {
    va_list ap;
    int     retlen  = 256;
    u8      *p;
    u8      *ret = NULL;

    if(fmt) {
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
    ret = malloc(retlen + 1);
    ret[0] = 0;
    if(!fgets(ret, retlen, stdin)) return(NULL);
    for(p = ret; *p && (*p != '\n') && (*p != '\r'); p++);
    *p = 0;
    return(ret);
}



u8 *get_ea_value(u8 *data, int datalen, u8 *want_par) {
    static u8   *ret = NULL;
    int     len;
    u8      *p,
            *l,
            *rn,
            *par,
            *val;

    p = data;
    l = data + datalen;
    while(p < l) {
        val = NULL;
        for(rn = p; rn < l; rn++) {
            if(*rn == '=') val = rn;
            if((*rn == '\r') || (*rn == '\n') || !*rn) break;
        }
        par = p;
        if(val && (strlen(want_par) == (val - par)) && !strnicmp(want_par, par, val - par)) {
            val++;
            len = rn - val;
            ret = realloc(ret, len + 1);
            memcpy(ret, val, len);
            ret[len] = 0;
            return(ret);
        }
        p = rn + 1;
    }
    return(NULL);
}



int vspr(u8 **buff, u8 *fmt, va_list ap) {
    int     len,
            mlen;
    u8      *ret;

    mlen = strlen(fmt) + 128;

    for(;;) {
        ret = malloc(mlen);
        if(!ret) return(0);     // return(-1);
        len = vsnprintf(ret, mlen, fmt, ap);
        if((len >= 0) && (len < mlen)) break;
        if(len < 0) {           // Windows style
            mlen += 128;
        } else {                // POSIX style
            mlen = len + 1;
        }
        FREEX(ret);
    }

    *buff = ret;
    return(len);
}



u8 *string_to_execute(u8 *str, u8 *ip, int port) {
#define QUICK_ALLOC(X) \
            if((newsz + X) >= totsz) { \
                totsz = newsz + X + 1024; \
                new = realloc(new, totsz + 1); \
            }
    int     newsz   = 0,
            totsz   = 0;
    u8      *p,
            *new    = NULL;

    totsz = strlen(str) + 1024;
    new = malloc(totsz + 1);
#ifdef WIN32
    newsz = sprintf(new, "start ");
#endif
    for(p = str; *p;) {
        if(!strncmp(p, "#IP", 3)) {
            QUICK_ALLOC(32)
            newsz += sprintf(new + newsz, "%s", ip);
            p += 3;
        } else if(!strncmp(p, "#PORT", 5)) {
            QUICK_ALLOC(32)
            newsz += sprintf(new + newsz, "%u", port);
            p += 5;
        } else {
            QUICK_ALLOC(1)
            new[newsz++] = *p;
            p++;
        }
    }
    new = realloc(new, newsz + 2 + 1);
    strcpy(new + newsz, " &");  // valid for both Win and others
    return(new);
}



int mysend(SSL *ssl_sd, int sd, u8 *data, int datasz) {
    if(ssl_sd) return(SSL_write(ssl_sd, data, datasz));
    return(send(sd, data, datasz, 0));
}



int myrecv(SSL *ssl_sd, int sd, u8 *data, int datasz) {
    if(ssl_sd) return(SSL_read(ssl_sd, data, datasz));
    return(recv(sd, data, datasz, 0));
}



void show_list(u8 *name) {
    int     i;
    u8      *prev_name = "";

    if(!quiet) {
        fprintf(fdout,
            "DESCRIPTION                                           GAMENAME\n"
            "-------------------------------------------------------------------------------\n");
    }

    for(i = 0; games_list[i].name; i++) {
        if(!stricmp(games_list[i].name, prev_name)) continue;   // don't show duplicates
        if(!name || (stristr(games_list[i].name, name) || stristr(games_list[i].description, name))) {
            fprintf(fdout, "%-53.53s %s\n",
                games_list[i].description[0] ? games_list[i].description : games_list[i].name,
                games_list[i].name);
        }
        prev_name = games_list[i].name;
    }
    /* unfortunately the list is necessary to know the port where connecting
    if(!name) {
        fprintf(fdout, "\n"
            "- like in gslist you need only to know the correct gamename also if it's not\n"
            "  included in the above list (which could be not updated)\n");
    }
    */
}



int enctypex_data_cleaner(unsigned char *dst, unsigned char *src, int max) {
    static const unsigned char strange_chars[] = {
                    ' ','E',' ',',','f',',','.','t',' ','^','%','S','<','E',' ','Z',
                    ' ',' ','`','`','"','"','.','-','-','~','`','S','>','e',' ','Z',
                    'Y','Y','i','c','e','o','Y','I','S','`','c','a','<','-','-','E',
                    '-','`','+','2','3','`','u','P','-',',','1','`','>','%','%','%',
                    '?','A','A','A','A','A','A','A','C','E','E','E','E','I','I','I',
                    'I','D','N','O','O','O','O','O','x','0','U','U','U','U','Y','D',
                    'B','a','a','a','a','a','a','e','c','e','e','e','e','i','i','i',
                    'i','o','n','o','o','o','o','o','+','o','u','u','u','u','y','b',
                    'y' };
    unsigned char   c,
                    *p;

    if(!dst) return(0);
    dst[0] = 0;
    if(!src) return(0);

    if(max < 0) max = strlen(src);

    for(p = dst; (c = *src) && (max > 0); src++, max--) {
        if(c == '\\') {                     // avoids the backslash delimiter
            *p++ = '/';
            continue;
        }

        if(enctypex_data_cleaner_level >= 1) {
            if(c == '^') {                  // Quake 3 colors
                //if(src[1] == 'x') {         // ^x112233 (I don't remember the game which used this format)
                    //src += 7;
                    //max -= 7;
                //} else
                if(isdigit(src[1]) || islower(src[1])) { // ^0-^9, ^a-^z... a good compromise
                    src++;
                    max--;
                } else {
                    *p++ = c;
                }
                continue;
            }
            if(c == 0x1b) {                 // Unreal colors
                src += 3;
                max -= 3;
                continue;
            }
            if(c < ' ') {                   // other colors
                continue;
            }
        }

        if(enctypex_data_cleaner_level >= 2) {
            if(c >= 0x7f) c = strange_chars[c - 0x7f];
        }

        if(enctypex_data_cleaner_level >= 3) {
            switch(c) {                     // html/SQL injection (paranoid mode)
                case '\'':
                case '\"':
                case '&':
                case '^':
                case '?':
                case '{':
                case '}':
                case '(':
                case ')':
                case '[':
                case ']':
                case '-':
                case ';':
                case '~':
                case '|':
                case '$':
                case '!':
                case '<':
                case '>':
                case '*':
                case '%':
                case ',': c = '.';  break;
                default: break;
            }
        }

        if((c == '\r') || (c == '\n')) {    // no new line
            continue;
        }
        *p++ = c;
    }
    *p = 0;
    return(p - dst);
}



// note that this function modifies the input string
void handle_server_info(u8 *data, int datalen, int show_server_info, u32 *ret_ip, u16 *ret_port) {
    static  u8  infostr[8192];  // close to fragmentsize
    u32     ip       = 0;
    u16     hostport = 0;
    u8      *l,
            *p,
            *rn,
            *par,
            *val;

    *ret_ip    = 0;
    *ret_port  = 0;
    infostr[0] = 0;

    p = data;
    l = data + datalen;
    while(p < l) {
        val = NULL;
        for(rn = p; rn < l; rn++) {
            if(*rn == '=') val = rn;
            if((*rn == '\r') || (*rn == '\n') || !*rn) break;
        }
        par = p;
        if(val) {
            *rn    = 0;
            *val++ = 0;
            //if(!strnicmp(par, "B-", 2)) par += 2;
            //if(!strnicmp(par, "U-", 2)) par += 2;
            if(!stricmp(par, "HN")) {
                par = "adminname";
            } else if(!stricmp(par, "N")) {
                par = "hostname";
            } else if(!stricmp(par, "I")) {
                par = "hostaddr";
                ip = inet_addr(val);
                //if(ip == INADDR_NONE) IPv6 ???;   // example 0x800155ee1a1f34c0
            } else if(!stricmp(par, "HU")) {
                par = "admin_userid";
            } else if(!stricmp(par, "V")) {
                par = "gamever";
            } else if(!stricmp(par, "P")) {
                par = "hostport";
                hostport = atoi(val);
            //} else if(!stricmp(par, "QP")) {  // other players or queryport ???
                //par = "queryport";
            } else if(!stricmp(par, "MP")) {
                par = "maxplayers";
            } else if(!stricmp(par, "PW")) {
                par = "password";
            } else if(!stricmp(par, "PL")) {
                par = "platform";
            } else if(!stricmp(par, "AP")) {
                par = "numplayers";
            } else if(!stricmp(par, "TID")) {   // skip
                par = NULL;
            } else if(!stricmp(par, "LID")) {   // skip
                par = NULL;
            }
            // the B-U-Password field is the md5 of the join password... crazy EA
            if(par && ((strlen(infostr) + 1 + strlen(par) + 1 + strlen(val) + 1) < sizeof(infostr))) {
                p = infostr + strlen(infostr);  // p can be reused here
                *p++ = '\\';
                p += enctypex_data_cleaner(p, par, sizeof(infostr) - (p - infostr));
                *p++ = '\\';
                p += enctypex_data_cleaner(p, val, sizeof(infostr) - (p - infostr));
                *p = 0;
            }
        }
        p = rn + 1;
    }

    *ret_ip     = ip;
    *ret_port   = hostport;
    if(show_server_info) {
        fprintf(fdout, "%s:%hu %s\n", ip2str(ip), hostport, infostr); // gslist compatible
    }
}



void show_help(void) {
    fprintf(stdout, "\n"
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "-a U P G       the account for accessing the fesl server composed by username,\n"
        "               password and game for which it has been registered that can be\n"
        "               the same of -n depending by where it has been activated (set it\n"
        "               to \"\" for avoiding to specify the same one used with -n)\n"
        "               example: -a myusername mypassword mohair-pc\n"
        "-A             create a new account, if -a is set then will be used these U P G\n"
        "               example: -A -a newuser newpass mohair-pc\n"
        "-n GAMENAME    servers list of the game GAMENAME (use -l or -s to know it)\n"
        //"               you can also specify multiple GAMENAMEs: -n GN1,GN2,...,GNN\n"
        "-l             complete list of supported games and their details\n"
        "-s PATTERN     search for games in the database (case insensitve)\n"
        //"-u             update the database of supported games (debug, not implemented)\n"
        //"-f FILTERS     specify a filter to apply to the servers list. Use -f ? for help\n"
        "-r \"prog...\"   lets you to execute a specific program for each IP found.\n"
        "               there are 2 available parameters: #IP and #PORT automatically\n"
        "               substituited with the IP and port of the each online game server\n"
        "-o OUT         specify a different output for the servers list (default output\n"
        "               is screen). Use -o ? for the list of options\n"
        "-q             quiet output, many informations will be not shown\n"
        "-x S[:P][:SSL] specify a different master server (S) and port (P is optional)\n"
        "               default is automatically based on the gamename\n"
        "-L SEC         continuous servers list loop each SEC seconds\n"
        //"-c             list of country codes to use with the \"country\" filter\n"
        "-X INFO        show the informations for each server instead of the IP list,\n"
        "               INFO is not handled at the moment so use just -X none\n"
        "-C             do not filter colors from the game info replied by the servers\n"
        "-v             debug, show the data sent and received from the master servers\n"
        "-V             debug, get the info about the theater server and quit\n"
        "-F S T FILES   experimental debug option that allows to send custom FILEs to\n"
        "               the fesl or theater server, T is the 4 chars type. example:\n"
        "               -F fesl achi GetAchievementDefinitionsByGroup_file.txt\n"
        "               -F theater LLST,LLST,ABCD filter1.txt,filter2.txt,abcd.txt\n"
        "-S PORT        experimental fake fesl server on port PORT (one client at time)\n"
        "\n", "ealist");
}



void show_output_help(void) {
    fputs("\n"
        "  1 = text output to a file for each game (ex: serioussam.gsl).\n"
        "      string: 1.2.3.4:1234 (plus a final line-feed)\n"
        "  2 = text output as above but to only one file ("FILEOUT")\n"
        "  3 = binary output to a file for each game: 4 bytes IP, 2 port\n"
        "      example: (hex) 7F0000011E62 = 127.0.0.1 7778\n"
        "  4 = binary output as above but to only one file ("FILEOUT")\n"
        "  5 = exactly like 1 but to stdout\n"
        "  6 = hexadecimal visualization of the raw servers list as is\n"
        "  FILENAME = if OUT is a filename all the screen output will be\n"
        "             dumped into the file FILENAME\n"
        "\n", stdout);
}



u8 *ip2str(u32 ip) {
    static u8   data[16];

    sprintf(data, "%u.%u.%u.%u",
        (ip & 0xff), ((ip >> 8) & 0xff), ((ip >> 16) & 0xff), ((ip >> 24) & 0xff));
    return(data);
}



int ea_send(SSL *ssl_sd, int sd, u8 *type1, u32 type2, u8 *fmt, ...) {
    va_list ap;
    static int  buffsz  = 0;    // fast solution
    static u8   *buff   = NULL;
    static int  counter = 0;
    int     slen,
            len;
    u8      *data;

    va_start(ap, fmt);
    len = vspr(&data, fmt, ap);
    va_end(ap);
    len++;  // EA uses the final NULL delimiter

    slen = 12 + len;
    if(slen > buffsz) {
        buffsz = slen;
        buff = realloc(buff, slen);
        if(!buff) std_err();
    }
    memcpy(buff, type1, 4);
    //if(type2 & 0x80000000) {
    if((type2 & 0xc0000000) == 0xc0000000) {        // this thing is useful to keep the counter of the
        if((type2 & 0x00ffffff) == 1) counter = 0;  // packets so that I don't need
        counter++;                                  // to modify my code if I add/remove one ea_send
        type2 = (type2 & 0xff000000) | counter;
    }
    putxx(buff + 4, type2, 4);
    putxx(buff + 8, slen, 4);
    memcpy(buff + 12, data, len);
    if(verbose) fprintf(stdout, "\n### SEND DUMP (%4.4s 0x%08x) ###\n%.*s\n", type1, type2, len, data);
    free(data);

    if(mysend(ssl_sd, sd, buff, slen) != slen) return(-1);
    return(0);
}



u8 *ea_recv(SSL *ssl_sd, int sd, int *ret_len, u8 *type) {
    static int  buffsz  = 0;
    static u8   *buff   = NULL;
    u32     len,
            type2;
    u8      header[12],
            *txn,
            *localizedMessage,
            *errorCode;

    *ret_len = -1;
    for(;;) {
        if(recv_tcp(ssl_sd, sd, header, 12) < 0) return(NULL);
        if(type) memcpy(type, header, 4);
        type2 = getxx(header + 4, 4);
        len   = getxx(header + 8, 4);
        len -= 12;
        if((int)len < 0) return(NULL);

        if(len > buffsz) {
            buffsz = len;
            buff = realloc(buff, len);
            if(!buff) std_err();
        }

        if(recv_tcp(ssl_sd, sd, buff, len) < 0) return(NULL);
        if(verbose) fprintf(stdout, "\n### RECV DUMP (%4.4s 0x%08x) ###\n%.*s\n", header, type2, len, buff);

        txn = get_ea_value(buff, len, "TXN");
        errorCode = get_ea_value(buff, len, "errorCode");
        if(!memcmp(header, "PING", 4)) {    // automatically reply to ping
            if(ea_send(ssl_sd, sd, "PING", type2,
                "TID=0\n") < 0) return(NULL);
        } else if(txn && !stricmp(txn, "Ping")) {
            if(ea_send(ssl_sd, sd, "fsys", 0x80000000,
                "TXN=Ping\n") < 0) return(NULL);
        //} else if(txn && !stricmp(txn, "MemCheck")) { // must be handled at part
            //if(ea_send(ssl_sd, sd, "fsys", 0x80000000,
                //"TXN=MemCheck\n"
                //"result=\n") < 0) return(NULL);
        } else if(errorCode && (atoi(errorCode) != 0)) {    // != 0?
            localizedMessage = get_ea_value(buff, len, "localizedMessage");
            fprintf(stderr, "\n"
                "Error received from the server:\n"
                "      %s\n"
                "\n", localizedMessage ? localizedMessage : buff);
            fprintf(stderr, "\n- dump follows:\n---\n%.*s\n---\n", len, buff);
            exit(1);
        } else {
            break;
        }
    }

    *ret_len = len;
    return(buff);
}



int recv_tcp(SSL *ssl_sd, int sd, u8 *data, int datalen) {
    int     len,
            t;

    for(len = 0; len < datalen; len += t) {
        if(!ssl_sd) {   // timeout can't be used with ssl because ssl is a layer over TCP
            if(timeout(sd, 10) < 0) return(-1);
        }
        t = myrecv(ssl_sd, sd, data + len, datalen - len);
        if(t <= 0) return(-1);
    }
    return(len);
}



static const u8 SSL_CERT_X509[] =   // x509 –in input.crt –inform PEM –out output.crt –outform DER
"\x30\x82\x03\x07\x30\x82\x02\x70\xa0\x03\x02\x01\x02\x02\x09\x00"
"\x85\x3a\x6e\x0a\xa4\x3c\x6b\xec\x30\x0d\x06\x09\x2a\x86\x48\x86"
"\xf7\x0d\x01\x01\x05\x05\x00\x30\x61\x31\x0b\x30\x09\x06\x03\x55"
"\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x14"
"\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x07\x14\x02\x22\x22"
"\x31\x0b\x30\x09\x06\x03\x55\x04\x0a\x14\x02\x22\x22\x31\x0b\x30"
"\x09\x06\x03\x55\x04\x0b\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03"
"\x55\x04\x03\x14\x02\x22\x22\x31\x11\x30\x0f\x06\x09\x2a\x86\x48"
"\x86\xf7\x0d\x01\x09\x01\x16\x02\x22\x22\x30\x1e\x17\x0d\x30\x39"
"\x30\x31\x30\x34\x30\x33\x31\x34\x33\x33\x5a\x17\x0d\x31\x30\x30"
"\x31\x30\x34\x30\x33\x31\x34\x33\x33\x5a\x30\x61\x31\x0b\x30\x09"
"\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55"
"\x04\x08\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x07\x14"
"\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x0a\x14\x02\x22\x22"
"\x31\x0b\x30\x09\x06\x03\x55\x04\x0b\x14\x02\x22\x22\x31\x0b\x30"
"\x09\x06\x03\x55\x04\x03\x14\x02\x22\x22\x31\x11\x30\x0f\x06\x09"
"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x02\x22\x22\x30\x81\x9f"
"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03"
"\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xc5\xe3\x3f\x2d\x8f\x98"
"\xc2\x2a\xef\x71\xea\x40\x21\x54\x3f\x08\x62\x9c\x7b\x39\x22\xfd"
"\xda\x80\x1f\x21\x3e\x8d\x68\xcf\x8e\x6b\x70\x98\x95\x2c\x1e\x4e"
"\x79\x39\x45\xf5\xa3\xd9\x20\x54\x85\x79\x36\xf5\x08\xbe\xa0\xa6"
"\x03\x80\x60\x21\xd6\xbc\xde\xf8\xed\xe8\x73\x02\x96\x84\xcb\xb4"
"\xff\x72\x89\xf4\x56\x41\xf6\x28\xf6\x6b\x9f\x0c\x1d\xe0\x9b\x21"
"\xcb\x86\x08\xdf\x6b\xc1\x8a\xd6\xa3\x52\x2f\xfa\xd8\x5a\x2c\x86"
"\x52\x0d\x75\x2d\xf6\x17\x11\xa7\x17\xad\xc2\x3b\xd8\x0f\xcf\xb7"
"\x2b\x2c\x8a\xc4\xcd\x2d\x94\xe4\x15\x75\x02\x03\x01\x00\x01\xa3"
"\x81\xc6\x30\x81\xc3\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14"
"\x00\x6b\x12\xa2\xb9\x10\x90\xe4\xe5\xe8\xff\xec\x5c\x24\x44\xee"
"\xed\xc1\x66\xb7\x30\x81\x93\x06\x03\x55\x1d\x23\x04\x81\x8b\x30"
"\x81\x88\x80\x14\x00\x6b\x12\xa2\xb9\x10\x90\xe4\xe5\xe8\xff\xec"
"\x5c\x24\x44\xee\xed\xc1\x66\xb7\xa1\x65\xa4\x63\x30\x61\x31\x0b"
"\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06"
"\x03\x55\x04\x08\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04"
"\x07\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x0a\x14\x02"
"\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x0b\x14\x02\x22\x22\x31"
"\x0b\x30\x09\x06\x03\x55\x04\x03\x14\x02\x22\x22\x31\x11\x30\x0f"
"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x02\x22\x22\x82"
"\x09\x00\x85\x3a\x6e\x0a\xa4\x3c\x6b\xec\x30\x0c\x06\x03\x55\x1d"
"\x13\x04\x05\x30\x03\x01\x01\xff\x30\x0d\x06\x09\x2a\x86\x48\x86"
"\xf7\x0d\x01\x01\x05\x05\x00\x03\x81\x81\x00\x33\xb1\xd0\x31\x04"
"\x17\x67\xca\x54\x72\xbc\xb7\x73\x5a\x8f\x1b\x23\x25\x7d\xcb\x23"
"\xae\x1b\x9b\xd2\x92\x80\x09\x5d\x20\x24\xd2\x73\x6f\xe7\x5a\xaf"
"\x9e\xd0\xdd\x50\x61\x96\xbf\x7c\x2d\xa1\x0a\xc4\x88\xf7\xe0\xc6"
"\xc3\x04\x35\x6f\xac\xd5\xd1\xfd\x55\xab\x6c\x99\xc7\x66\x72\xb8"
"\x70\x22\xcb\xd3\x8c\xa7\x18\x17\x2e\x25\x2f\x33\x5c\x57\x82\x67"
"\x0e\x29\xeb\x81\x74\xd3\xa3\x54\xfa\x08\xba\x87\x50\x18\xab\xc5"
"\x15\x69\xce\x4a\x73\x3b\xee\x12\x4d\x1c\x63\x11\x9b\xdf\x4d\xa1"
"\x38\x0d\xb6\x1d\xfb\xd6\xb8\x5b\xc2\x10\xd9";

static const u8 SSL_CERT_RSA[] =    // rsa –in input.key –inform PEM –out output.key –outform DER
"\x30\x82\x02\x5b\x02\x01\x00\x02\x81\x81\x00\xc5\xe3\x3f\x2d\x8f"
"\x98\xc2\x2a\xef\x71\xea\x40\x21\x54\x3f\x08\x62\x9c\x7b\x39\x22"
"\xfd\xda\x80\x1f\x21\x3e\x8d\x68\xcf\x8e\x6b\x70\x98\x95\x2c\x1e"
"\x4e\x79\x39\x45\xf5\xa3\xd9\x20\x54\x85\x79\x36\xf5\x08\xbe\xa0"
"\xa6\x03\x80\x60\x21\xd6\xbc\xde\xf8\xed\xe8\x73\x02\x96\x84\xcb"
"\xb4\xff\x72\x89\xf4\x56\x41\xf6\x28\xf6\x6b\x9f\x0c\x1d\xe0\x9b"
"\x21\xcb\x86\x08\xdf\x6b\xc1\x8a\xd6\xa3\x52\x2f\xfa\xd8\x5a\x2c"
"\x86\x52\x0d\x75\x2d\xf6\x17\x11\xa7\x17\xad\xc2\x3b\xd8\x0f\xcf"
"\xb7\x2b\x2c\x8a\xc4\xcd\x2d\x94\xe4\x15\x75\x02\x03\x01\x00\x01"
"\x02\x81\x80\x59\x45\x5c\x11\xf4\xae\xc8\x21\x50\x65\xc6\x74\x69"
"\xd4\xb4\x9e\xd6\xc5\x9a\xfd\x3a\xa0\xe4\x7a\x5a\x10\xc8\x44\x48"
"\xdd\x21\x75\xac\x94\xd8\xee\xcf\x39\x3d\x8c\xad\xd7\xd3\xb3\xb6"
"\xd7\x0a\x63\x95\x7c\x53\x16\x94\x28\x70\x79\xf0\x64\x33\x98\x7e"
"\xca\x33\xa0\x97\x38\x01\xe9\x06\x9b\x5c\x15\x3d\x89\xa3\x40\x2a"
"\x54\xb1\x79\x15\xf1\x7c\xfd\x18\xca\xdf\x53\x42\x6c\x8a\x0b\xc1"
"\x18\x70\xea\x7e\x00\x64\x07\x84\x37\xf2\x1b\xf5\x2a\x22\xe9\xd6"
"\xfa\x03\xc6\x7f\xaa\xc8\xa2\xa3\x67\x2a\xd3\xdd\xae\x36\x47\xc1"
"\x4f\x13\xe1\x02\x41\x00\xec\x61\x11\xbf\xcd\x87\x03\xa6\x87\xc9"
"\x2f\x1d\x80\xc1\x73\x5f\x19\xe7\x7c\xb9\x67\x7e\x49\x58\xbf\xab"
"\xd8\x37\x29\x22\x69\x79\xa4\x06\xcd\xac\x5f\x9e\xba\x12\x77\xf8"
"\x3e\xd2\x6a\x06\xb5\x90\xe4\xfa\x23\x86\xff\x41\x1b\x10\xbe\xe4"
"\x9d\x29\x75\x7c\xe6\x49\x02\x41\x00\xd6\x50\x40\xfc\xc9\x49\xad"
"\x69\x55\xc7\xa3\x5d\x51\x05\x5b\x41\x2b\xd2\x5a\x74\xf8\x15\x49"
"\x06\xf0\x1a\x6f\x7d\xb6\x65\x17\xa0\x64\xff\x7a\xd6\x99\x54\x0d"
"\x53\x95\x9f\x6c\x43\xde\x27\x1b\xe9\x24\x13\x43\xd5\xda\x22\x85"
"\x1d\xa7\x55\xa5\x4d\x0f\x5e\x45\xcd\x02\x40\x51\x92\x4d\xe5\xba"
"\xaf\x54\xfb\x2a\xf0\xaa\x69\xab\xfd\x16\x2b\x43\x6d\x37\x05\x64"
"\x49\x98\x56\x20\x0e\xd5\x56\x73\xc3\x84\x52\x8d\xe0\x2b\x29\xc8"
"\xf5\xa5\x90\xaa\x05\xe8\xe8\x03\xde\xbc\xd9\x7b\xab\x36\x87\x67"
"\x9e\xb8\x10\x57\x4f\xdd\x4c\x69\x56\xe8\xc1\x02\x40\x27\x02\x5a"
"\xa1\xe8\x9d\xa1\x93\xef\xca\x33\xe1\x33\x73\x2f\x26\x10\xac\xec"
"\x4c\x28\x2f\xef\xa7\xf4\xa2\x4b\x32\xed\xb5\x3e\xf4\xb2\x0d\x92"
"\xb5\x67\x19\x56\x87\xa5\x4f\x6c\x6c\x7a\x0e\x52\x55\x40\x7c\xc5"
"\x37\x32\xca\x5f\xc2\x83\x07\xe2\xdb\xc0\xf5\x5e\xed\x02\x40\x1b"
"\x88\xf3\x29\x8d\x6b\xdb\x39\x4c\xa6\x96\x6a\xd7\x6b\x35\x85\xde"
"\x1c\x2c\x3f\x0c\x8d\xff\xf5\xc1\xeb\x25\x3c\x56\x63\xaa\x03\xe3"
"\x10\x24\x87\x98\xd4\x73\x62\x4a\x51\x3b\x01\x9a\xda\x73\xf2\xcd"
"\xd6\xbb\xe3\x3e\x37\xb3\x19\xd9\x82\x91\x07\xdf\xd0\xa9\x80";

void set_date(u8 *str) {
    time_t  datex;
    struct  tm  *tmx;
    static const u8 *months[12] = {
            "Jan","Feb","Mar","Apr","May","Jun",
            "Jul","Aug","Sep","Oct","Nov","Dec" };

    time(&datex);
    tmx = localtime(&datex);
    sprintf(str,
        "%3s-%02d-%4d %02d%%3a%02d%%3a%02d UTC",
        months[tmx->tm_mon], tmx->tm_mday, tmx->tm_year % 100,
        tmx->tm_hour, tmx->tm_min, tmx->tm_sec);
}

int rndxx(u8 *data, int len) {
    static const char table[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
    static u32  rnd = 0;
    int     i;

    if(!rnd) rnd = ~time(NULL);
    len = rnd % len;
    if(len < 10) len = 10;

    for(i = 0; i < len; i++) {
        rnd = ((rnd * 0x343FD) + 0x269EC3) >> 1;
        data[i] = table[rnd % (sizeof(table) - 1)];
    }
    data[i] = 0;
    return(i);
}

// do NOT make it threaded, all the functions in ealist are monothread only!
int fake_fesl_server(int sd) {
    SSL_CTX *ctx_sd     = NULL;
    SSL     *ssl_sd     = NULL;
    unsigned int    pid;
    int     len,
            cnt;
    u8      curtime[64],
            type[4],
            lkey[16],
            *buff,
            *txn,
            *p,
            *l,
            *user;

    rndxx(lkey, sizeof(lkey) - 1);
    pid = (~time(NULL)) & 0x7fffffff;
    user = strdup("user");
    cnt = 0;

    if(dossl) {
        ctx_sd = SSL_CTX_new(SSLv3_method());
        if(!ctx_sd) goto quit;
        SSL_COMPAT(ctx_sd)

        if(!SSL_CTX_use_certificate_ASN1(ctx_sd, sizeof(SSL_CERT_X509) - 1, SSL_CERT_X509) ||
           !SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx_sd, SSL_CERT_RSA, sizeof(SSL_CERT_RSA) - 1)) {
            fprintf(stderr, "\nError: problems with the loading of the certificate in memory\n");
            exit(1);
        }
        SSL_CTX_set_verify_depth(ctx_sd, 1);  // #if (OPENSSL_VERSION_NUMBER < 0x00905100L)

        ssl_sd = SSL_new(ctx_sd);
        if(!ssl_sd) goto quit;
        SSL_set_fd(ssl_sd, sd);
        if(SSL_accept(ssl_sd) < 0) goto quit;
    }

    for(;;) {
        if(timeout(sd, 120) < 0) {  // not exact for ssl but should be ok
            // yeah ping would be better but it's handled by ea_recv causing troubles
            if(ea_send(ssl_sd, sd, type, 0x80000000,
                "TXN=%s\n"
                "memcheck.[]=0\n"
                "type=0\n"
                "salt=%u\n",
                "MemCheck",
                time(NULL)) < 0) goto quit;
            continue;
        }
        buff = ea_recv(ssl_sd, sd, &len, type);
        if(!buff || (len < 0)) goto quit;

        /*
            AddAccount
            AddSubAccount
            DisableSubAccount
            GameSpyPreAuth
            GetAccount
            GetCountryList
            GetCreditCardInfo
            GetCreditCardTypes
            GetLockerURL
            GetScreenNamesByUserIds
            GetSubAccounts
            GetTelemetryToken
            GetTos
            GetUserIdsByXuids
            GetXuidsByGamertags
            GetXuidsByUserIds
            Login
            LoginSubAccount
            LookupUserInfo
            NuAddAccount
            NuAddPersona
            NuCreateEncryptedToken
            NuDisablePersona
            NuEntitleGame
            NuEntitleUser
            NuGetAccount
            NuGetAccountByNuid
            NuGetAccountByPS3Ticket
            NuGetEntitlementCount
            NuGetEntitlements
            NuGetPersonas
            NuGetTos
            NuLogin
            NuLoginPersona
            NuLookupUserInfo
            NuPS3AddAccount
            NuPS3Login
            NuSearchOwners
            NuSuggestPersonas
            NuUpdateAccount
            NuUpdatePassword
            NuXBL360AddAccount
            NuXBL360Login
            RegisterGame
            SendAccountName
            SendPassword
            SuggestScreenNames
            SuggestSubScreenNames
            TransactionException
            UpdateAccount
            UpdateCreditCardInfo
            UpdatePassword
            XBL360AddAccount
            XBL360Login
            XBL360UpdateAccount
            XBLAddAccount
            XBLLogin
        */

        txn = get_ea_value(buff, len, "TXN");
        if(!txn) continue;

        p = get_ea_value(buff, len, "nuid");
        if(!p) p = get_ea_value(buff, len, "name");
        if(p) {
            free(user);
            user = strdup(p);
        }

        // the following handles both Nu and non-Nu commands
        #define TXN_CMP(X)  (!stricmp(txn, X) || !stricmp(txn, "Nu"X))

        if(TXN_CMP("Hello")) {
            p = get_ea_value(buff, len, "clientString");
            if(!p) p = "core";
            l = strchr(p, '-');
            if(l) *l++ = 0;

            set_date(curtime);
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "domainPartition.domain=eagames\n"
                "messengerIp=messaging.ea.com\n"
                "messengerPort=13505\n"
                "domainPartition.subDomain=%s\n"    // e.g.: CNCRA
                "activityTimeoutSecs=0\n"
                "curTime=\"%s\"\n"
                "theaterIp=%s%s%s.theater.ea.com\n"
                "theaterPort=%u\n",
                txn,
                p,
                curtime,
                p, l ? "-" : "", l ? (char*)l : "",
                fake_server_port + 5) < 0) goto quit;

            if(ea_send(ssl_sd, sd, type, 0x80000000,
                "TXN=%s\n"
                "memcheck.[]=0\n"
                "type=0\n"
                "salt=%u\n",
                "MemCheck",
                time(NULL)) < 0) goto quit;

        } else if(TXN_CMP("Goodbye")) {
            goto quit;

        } else if(TXN_CMP("MemCheck")) {
            // do NOTHING or will loop!

        } else if(TXN_CMP("GetTos")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "data=\n"
                "decodedSize=0\n"
                "size=0\n") < 0) goto quit;

        } else if(TXN_CMP("Login")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "lkey=%s\n"
                "nuid=%s@example.com\n"
                "displayName=%u\n"
                "profileId=%u\n"
                "userId=%u\n",
                txn,
                lkey,
                user,
                user,
                pid,
                pid) < 0) goto quit;

        } else if(TXN_CMP("GetPersonas")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "personas.[]=1\n"
                "personas.0=%s\n",
                txn,
                user) < 0) goto quit;

        } else if(TXN_CMP("GetAccount")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "nuid=%s@example.com\n"
                "DOBDay=1\n"
                "DOBMonth=1\n"
                "DOBYear=1980\n"
                "userId=%u\n"
                "globalOptin=0\n"
                "thirdPartyOptin=0\n"
                "language=en\n"
                "country=US\n",
                txn,
                user,
                pid) < 0) goto quit;

        } else if(TXN_CMP("GetStats")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "stats.[]=0\n",
                txn) < 0) goto quit;

        } else if(TXN_CMP("LoginPersona")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "flkey=%s\n"
                "profileId=%u\n"
                "userId=%u\n",
                txn,
                lkey,
                pid,
                pid) < 0) goto quit;

        } else if(TXN_CMP("GetPingSites")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "pingSite.[]=1\n"
                "minPingSitesToPing=0\n"
                "pingSite.0.name=iad\n"
                "pingSite.0.type=0\n"
                "pingSite.0.addr=159.153.105.104\n",
                txn) < 0) goto quit;

        } else if(TXN_CMP("GameSpyPreAuth")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "challenge=pass\n"  // this is the password used in gs_login_server
                "ticket=O%%3d%%3d%%3d\n",   // base64 of ""
                txn) < 0) goto quit;

        } else if(TXN_CMP("GetLockerURL")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "URL=http%%3a//easo.ea.com/fileupload/locker2.jsp\n",
                txn) < 0) goto quit;

        } else if(TXN_CMP("GetAccount")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "parentalEmail=parents@ea.com\n"
                "countryCode=US\n"
                "countryDesc=\"United States of America\"\n"
                "thirdPartyMailFlag=0\n"
                "dobDay=1\n"
                "dobMonth=1\n"
                "dobYear=1980\n"
                "name=%s\n"
                "email=%s@example.com\n"
                "profileID=%u\n"
                "userId=%u\n"
                "zipCode=90094\n"
                "gender=U\n"
                "eaMailFlag=0\n",
                txn,
                pid,
                pid,
                user,
                user) < 0) goto quit;

        } else if(TXN_CMP("GetCountryList")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "data=\n"
                "decodedSize=0\n"
                "size=0\n") < 0) goto quit;

        } else if(TXN_CMP("GetSubAccounts")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "subAccounts.[]=0\n",
                txn) < 0) goto quit;

        } else if(TXN_CMP("SuggestPersonas")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "names.[]=0\n",
                txn) < 0) goto quit;

        } else if(TXN_CMP("GetTelemetryToken")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "telemetryToken=\n"
                "enabled=\n"
                "filters=\n"
                "disabled=\n",
                txn) < 0) goto quit;

        } else if(TXN_CMP("SearchOwners")) {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "users.[]=1\n"
                "users.0.name=%s\n"
                "users.0.id=%u\n"
                "users.0.type=1\n"
                "nameSpaceId=cem_ea_id\n",
                txn,
                user,
                pid) < 0) goto quit;

        } else {
            if(ea_send(ssl_sd, sd, type, 0x80000000 | ++cnt,
                "TXN=%s\n"
                "%s.[]=0\n",
                txn,
                (!strnicmp(txn, "Get", 3)) ? txn + 3 : txn) < 0) goto quit;
        }
    }

quit:
    if(dossl) {
        if(ssl_sd) {
            SSL_shutdown(ssl_sd);
            SSL_free(ssl_sd);
        }
        if(ctx_sd) SSL_CTX_free(ctx_sd);
    }
    if(sd) close(sd);
    if(user) free(user);
    fprintf(stderr, "- disconnected\n");
    return(0);
}



void myalloc(u8 **data, int wantsize, int *currsize) {
    if(!wantsize) return;
    if(wantsize <= *currsize) {
        if(*currsize > 0) return;
    }
    *data = realloc(*data, wantsize);
    if(!*data) std_err();
    *currsize = wantsize;
}



int putxx(u8 *data, u32 num, int bytes) {
    int     i;

    for(i = 0; i < bytes; i++) {
        //data[i] = num >> (i << 3);    // little
        data[i] = num >> ((bytes - 1 - i) << 3);    // big
    }
    return(bytes);
}



u32 getxx(u8 *data, int bytes) {
    u32     num;
    int     i;

    for(num = i = 0; i < bytes; i++) {
        //num |= (data[i] << (i << 3)); // little
        num |= (data[i] << ((bytes - 1 - i) << 3)); // big
    }
    return(num);
}



int timeout(int sock, int secs) {
    struct  timeval tout;
    fd_set  fd_read;

    tout.tv_sec  = secs;
    tout.tv_usec = 0;
    FD_ZERO(&fd_read);
    FD_SET(sock, &fd_read);
    if(select(sock + 1, &fd_read, NULL, NULL, &tout)
      <= 0) return(-1);
    return(0);
}



u32 resolv(char *host) {
    struct  hostent *hp;
    u32     host_ip;

    host_ip = inet_addr(host);
    if(host_ip == INADDR_NONE) {
        hp = gethostbyname(host);
        if(!hp) {
            fprintf(stderr, "\nError: Unable to resolv hostname (%s)\n", host);
            exit(1);
        } else host_ip = *(u32 *)hp->h_addr;
    }
    return(host_ip);
}



#ifndef WIN32
    void std_err(void) {
        perror("\nError");
        exit(1);
    }
#endif


