//------------------------------------------------------------------------------
// Ping utility for Zabbix monitoring agent on the TRAKT workstations.
// Artiom N.(cl)2013
//------------------------------------------------------------------------------
#ifndef WPING_H
#define WPING_H
//------------------------------------------------------------------------------
//#include <winsock2.h>
#include <windows.h>
#include <ipexport.h>
//------------------------------------------------------------------------------
/*#define IP_STATUS_BASE 11000
#define IP_SUCCESS 0
#define IP_BUF_TOO_SMALL 11001
#define IP_DEST_NET_UNREACHABLE 11002
#define IP_DEST_HOST_UNREACHABLE 11003
#define IP_DEST_PROT_UNREACHABLE 11004
#define IP_DEST_PORT_UNREACHABLE 11005
#define IP_NO_RESOURCES 11006
#define IP_BAD_OPTION 11007
#define IP_HW_ERROR 11008
#define IP_PACKET_TOO_BIG 11009
#define IP_REQ_TIMED_OUT 11010
#define IP_BAD_REQ 11011
#define IP_BAD_ROUTE 11012
#define IP_TTL_EXPIRED_TRANSIT 11013
#define IP_TTL_EXPIRED_REASSEM 11014
#define IP_PARAM_PROBLEM 11015
#define IP_SOURCE_QUENCH 11016
#define IP_OPTION_TOO_BIG 11017
#define IP_BAD_DESTINATION 11018
#define IP_ADDR_DELETED 11019
#define IP_SPEC_MTU_CHANGE 11020
#define IP_MTU_CHANGE 11021
#define IP_UNLOAD 11022
#define IP_GENERAL_FAILURE 11050
#define MAX_IP_STATUS 11050
#define IP_PENDING 11255
//------------------------------------------------------------------------------
typedef struct tagIP_INFO
{
   // Time To Live.
   u_char Ttl;
   // Type Of Service.
   u_char Tos;
   // IP flags.
   u_char IPFlags;
   // Size of options data.
   u_char OptSize;
   // Options data buffer.
   u_char FAR *Options;
} IP_INFO;
typedef IP_INFO* PIP_INFO;
//------------------------------------------------------------------------------
typedef struct tagICMP_ECHO_REPLY
{
   // Source address.
   u_long Source;
   // IP status.
   u_long Status;
   // Round trip time in milliseconds.
   u_long RTTime;
   // Reply data size.
   u_short DataSize;
   // Reserved for system use.
   u_short Reserved;
   // Reply data buffer.
   void FAR *pData;
   // Reply options.
   IPINFO ipInfo;
}
ICMP_ECHO_REPLY;
typedef IP_ECHO_REPLY* PICMP_ECHO_REPLY;
*/
//------------------------------------------------------------------------------
// ICMP.DLL export function pointers.
HANDLE (WINAPI *pIcmpCreateFile)(VOID);
BOOL (WINAPI *pIcmpCloseHandle)(HANDLE);
DWORD (WINAPI *pIcmpSendEcho)
      (HANDLE, DWORD, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
//------------------------------------------------------------------------------
// Ping options.

// Checking availability.
#define PING_OPT_AVAIL     0x01
// Up verbosity level.
#define PING_OPT_VERBOSE   0x02
// Don't call Sleep() between pings.
#define PING_OPT_NOSLEEP   0x04

//
// Default values.
//

// Delay between pings in ms.
#define PING_DEF_DELAY     1000
// Packets count.
#define PING_DEF_COUNT     3
// Packet size in bytes.
#define PING_DEF_DATA_SIZE 32
// Default ping function.
#define PING_DEF_FUNC      tpf_max

//
// Limitations.
//

#define PING_MAX_DATA_SIZE 0xffe0
// Maximum ping time (maximum retransmission time about 4 min.)
#define PING_MAX_TIME 250000

//------------------------------------------------------------------------------
// Some macroses.
#define REPLY_STRUCT_SIZE sizeof(ICMP_ECHO_REPLY)

//------------------------------------------------------------------------------
// Ping function for return ping value.
typedef enum
{
   tpf_avg, tpf_max, tpf_min
} t_ping_func;
//------------------------------------------------------------------------------
struct t_ping_data
{
   char        *host;
   DWORD       opts;
   t_ping_func ping_func;
   int         count;
   int         delay;
   size_t      buf_sz;
   char        *pattern;
};
//------------------------------------------------------------------------------
#endif
