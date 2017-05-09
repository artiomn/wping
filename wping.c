//------------------------------------------------------------------------------
#include <ws2tcpip.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
//------------------------------------------------------------------------------
#include "wping.h"
//------------------------------------------------------------------------------
void fprint_hexdump(FILE *fs, const unsigned char *data, const long data_sz,
                    const int bc)
{
   register int i;
   register int wl = bc / 5;

/*   assert(data       != NULL);
   assert(fs         != NULL);
   assert(data_sz    >  0);*/

   for (i = 0; i < data_sz; i++)
   {
      fprintf(fs, "0x%02X ", data[i]);
      if (wl && (((i + 1) % wl) == 0)) fprintf(fs, "\n");
   }
   return;
}
//------------------------------------------------------------------------------
BOOL load_icmp_dll(HANDLE *hndlICMP)
{
	*hndlICMP = LoadLibrary("ICMP.DLL");

   if (*hndlICMP == NULL)
   {
      fprintf(stderr, "Could not load ICMP.DLL!\n");
      return(0);
   }

   // Retrieve ICMP function pointers.
   pIcmpCreateFile  = (HANDLE (WINAPI *)(void))
	   GetProcAddress((HMODULE)*hndlICMP, "IcmpCreateFile");
   pIcmpCloseHandle = (BOOL (WINAPI *)(HANDLE))
	   GetProcAddress((HMODULE)*hndlICMP, "IcmpCloseHandle");
   pIcmpSendEcho = (DWORD (WINAPI *)
      (HANDLE, DWORD, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD))
      GetProcAddress((HMODULE)*hndlICMP, "IcmpSendEcho");
   // Check all the function pointers.
   if (pIcmpCreateFile    == NULL   || 
	    pIcmpCloseHandle   == NULL   ||
       pIcmpSendEcho      == NULL)
   {
      fprintf(stderr, "Error loading ICMP.DLL!\n");
      FreeLibrary((HMODULE)(*hndlICMP));
      return(FALSE);
   }

   return(TRUE);
}
//------------------------------------------------------------------------------
BOOL init_network()
{
   // Need min. 500 bytes, but sizeof(WSADATA) == 400 bytes.
   char lpWSAData[1024];
	WSADATA wsaData;

	// Init WinSock.
   // Ws2_32.dll initialization.
   if (WSAStartup(MAKEWORD(2, 2), (WSADATA*)&lpWSAData[0]) != 0)
   {
      fprintf(stderr, "Error: WSAStartup %d\n", WSAGetLastError());
      WSACleanup();
      return(FALSE);
   }

   return(TRUE);
}
//------------------------------------------------------------------------------
PICMP_ECHO_REPLY create_reply_buffer(char *buf, DWORD data_sz)
// Create ICMP reply structure.
// If error - return NULL.
// Result need to be destroyed somewhere.
{
   DWORD reply_sz             = REPLY_STRUCT_SIZE + data_sz;
   PICMP_ECHO_REPLY p_reply   = (PICMP_ECHO_REPLY)malloc(reply_sz);

   if (!p_reply) return(NULL);
   memset(p_reply, 0, reply_sz);

   p_reply->Data     = buf;
   p_reply->DataSize = data_sz;

   return(p_reply);
}
//------------------------------------------------------------------------------
void free_reply(PICMP_ECHO_REPLY *pecho_reply)
// Free memory, allocated by create_reply().
{
   free(pecho_reply);
}
//------------------------------------------------------------------------------
// Fills all the outpack, excluding ICMP header, but _including_
// timestamp area with supplied pattern.
static BOOL fill(char *patp, char *buffer, const DWORD buf_sz)
{
	int pat[16], pi;
   static int ps = sizeof(pat) / sizeof(int);
	char *cp;
   int buf_pos = 0, pat_len;

	for (cp = patp; *cp; cp++)
   {
		if (!isxdigit(*cp))
      {
			fprintf(stderr, "Error: patterns must be specified as hex digits.\n");
         return(FALSE);
      }
	}

   sscanf(patp,
         "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
         &pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5], &pat[6],
         &pat[7], &pat[8], &pat[9], &pat[10], &pat[11], &pat[12],
         &pat[13], &pat[14], &pat[15]);

   while (buf_pos < buf_sz)
   {
      pat_len = min(buf_sz - buf_pos, ps);
      for (pi = 0; pi < ps; pi++) buffer[buf_pos + pi] = pat[pi];
      buf_pos += pat_len;
	}

   return(TRUE);
}
//------------------------------------------------------------------------------
DWORD get_end_time(const DWORD end_time, struct t_ping_data *wping,
                   const DWORD rtt)
{
   switch (wping->ping_func)
   {
      case tpf_max:
         return(max(rtt, end_time));
      break;
      case tpf_avg:
         return(end_time + rtt);
      break;
      case tpf_min:
         return(min(rtt, end_time));
      break;
      default:
      break;
   }
   return(0);
}
//------------------------------------------------------------------------------
BOOL ping(struct t_ping_data *wping)
{
   // Internet address structure.
   struct in_addr iaDest;
   // Handle for IcmpCreateFile().
   HANDLE hndlFile = INVALID_HANDLE_VALUE;
   // IP options.
   IP_OPTION_INFORMATION IPInfo;
   // Replies count.
   DWORD rep_cnt;
   char  *buf                    = NULL;
   PICMP_ECHO_REPLY  echo_reply  = NULL;
   BOOL              ret_status  = FALSE;
   // Reply time.
   int               end_time;
   register int      i;
   // Ping with responses.
   DWORD             good_packets_cnt = 0;
   struct hostent    *phost_ent;

   while (TRUE)
   {
      if (wping->buf_sz > 0)
      {
         if (wping->buf_sz > PING_MAX_DATA_SIZE)
         {
            fprintf(stderr,
                    "Error: maximum ping data size = %ld, but you asked size = %ld\n",
                    PING_MAX_DATA_SIZE, wping->buf_sz);
            break;
         }
         if ((buf = malloc(wping->buf_sz)) == NULL)
         {
            fprintf(stderr, "Error: can't create data buffer [%s]!\n", strerror(errno));
            break;
         }
         if (wping->opts & PING_OPT_VERBOSE) printf("Data pattern: 0x%s\n", wping->pattern);

         if (!fill(wping->pattern, buf, wping->buf_sz))
         {
            fprintf(stderr, "Error: can't fill buffer [%s]!\n", strerror(errno));
            break;
         }

/*         if (wping->opts & PING_OPT_VERBOSE)
         {
            printf("Buffer data:\n");
		      fprint_hexdump(stdout, buf, wping->buf_sz, 80);
            printf("\n\n");
	      }*/

      }

      if ((echo_reply = create_reply_buffer(buf, wping->buf_sz)) == NULL)
      {
         fprintf(stderr, "Error: can't create reply [%s]!\n", strerror(errno));
         break;
      }

      // Lookup destination
      // Use inet_addr() to determine if we're dealing with a name
      // or an address.
      if ((iaDest.s_addr = inet_addr(wping->host)) == INADDR_NONE)
      {
         if ((phost_ent = gethostbyname(wping->host)) == NULL)
         {
            if (wping->opts & PING_OPT_VERBOSE) printf("Can't lookup destination!\n");
            break;
         }
         iaDest.s_addr = *((unsigned int*)phost_ent->h_addr_list[0]);
         // Doesn't work correctly. Why? I don't know.
         // gethostbyaddr((const char *)&iaDest, sizeof(struct in_addr), AF_INET);
      }

      // Get an ICMP echo request handle.
      hndlFile = pIcmpCreateFile();
      if (hndlFile == INVALID_HANDLE_VALUE)
      {
         fprintf(stderr, "Error: IcmpCreateFile() error (%s)!\n", strerror(errno));
         break;
      }

      // Set some reasonable default values.
      IPInfo.Ttl           = 255;
      IPInfo.Tos           = 0;
      IPInfo.Flags         = 0;
      IPInfo.OptionsSize   = 0;
      IPInfo.OptionsData   = NULL;

      ret_status = TRUE;
      if (wping->opts & PING_OPT_VERBOSE)
      {
         printf("Count = %d\nSize  = %d\nDelay = %d\nSending to \"%s\"\n\n",
                wping->count, wping->buf_sz + REPLY_STRUCT_SIZE, wping->delay,
                inet_ntoa(*((struct in_addr*)&(iaDest.s_addr))));
      }

      end_time = (wping->ping_func == tpf_min) ? PING_MAX_TIME : 0;
      for (i = 0; i < wping->count; i++)
      {
         echo_reply->Status   = IP_SUCCESS;
         // Reqest an ICMP echo:
         // icmpSendEcho(Handle from IcmpCreateFile(), Destination IP address,
         //              Pointer to buffer to send, Size of buffer in bytes,
         //              Request options, Reply buffer, Time to wait in milliseconds).
         rep_cnt = pIcmpSendEcho(hndlFile, iaDest.s_addr,
                                 buf, wping->buf_sz, &IPInfo, echo_reply,
                                 (REPLY_STRUCT_SIZE + wping->buf_sz), wping->delay);
         if (!(wping->opts & PING_OPT_NOSLEEP)) Sleep(wping->delay);

         if (((rep_cnt > 0)) && (echo_reply->Status == IP_SUCCESS))
         {
            while (rep_cnt--)
            {
               end_time = get_end_time(end_time, wping, echo_reply->RoundTripTime);
               if (wping->opts & PING_OPT_VERBOSE)
               {
                  printf("Received from:  %s\n",      inet_ntoa(*((struct in_addr*)&(echo_reply->Address))));
                  printf("Status:         %ld\n",     echo_reply->Status);
                  printf("Roundtrip time: %ld ms\n",  echo_reply->RoundTripTime);
                  printf("TTL:            %ld\n",     echo_reply->Options.Ttl);
                  printf("Bytes:          %ld\n\n",   echo_reply->DataSize);
               }
               good_packets_cnt++;
            }
         }
         else
         {
            if (wping->opts & PING_OPT_VERBOSE)
            {
               printf("Host \"%s\" (resolved: \"%s\") doesn't response!\n", wping->host, inet_ntoa(*((struct in_addr*)&(iaDest.s_addr))));
            }
            end_time += get_end_time(end_time, wping, wping->delay);
         }
      }

      ret_status = good_packets_cnt != 0;
      break;
   }

   if (!(wping->opts & PING_OPT_AVAIL))
   {
      if (ret_status)
      {
         printf("%0.3f\n",
                (wping->ping_func != tpf_avg) ? end_time : (float)end_time / (good_packets_cnt + 1));
      }
      else printf("-1\n");
   }

   free(buf);
   free(echo_reply);
   // Close the echo request file handle.
   pIcmpCloseHandle(hndlFile);
	return(ret_status);
}
//------------------------------------------------------------------------------
void usage(const char *p_name)
{
   printf("%s - ping utility for zabbix agents on \"TRAKT\" gates\n\n", p_name);
   printf("Usage:\n\t%s [-a] [-h] [-v] [-w] [-f <function>] [-c <count>] [-s <size>] [-W <delay>] <host>\n\n");
   printf("Parameters:\n");
   printf("\t-a - check availability (1 - host available, 0 - not)\n");
   printf("\t-w - don't call Sleep() between pings\n");
   printf("\t-f - ping time calculation function.\n\t     If '-a' option not presented [max, min, avg]\n");
   printf("\t-c - pings count\n");
   printf("\t-s - packet data size in bytes\n");
   printf("\t-W - period, while ping wait for response\n\t     and period for Sleep() between pings, ms\n");
   printf("\t-v - verbose\n");
   printf("\t-h - show help\n\n");
   printf("Artiom N.(cl)2013\n");
}
//------------------------------------------------------------------------------
int main(int argc, char **argv)
{
   struct t_ping_data   wping;
   int                  opt;
   HANDLE               hndlICMP;

   wping.opts        = 0;
   wping.count       = PING_DEF_COUNT;
   wping.buf_sz      = PING_DEF_DATA_SIZE;
   wping.delay       = PING_DEF_DELAY;
   wping.ping_func   = PING_DEF_FUNC;

   while ((opt = getopt(argc, argv, "ahvwf:c:s:W:")) != -1)
   {
      switch (opt)
      {
         case 'a':
         // Checking availability.
            wping.opts     |= PING_OPT_AVAIL;
         break;
         case 'v':
            wping.opts     |= PING_OPT_VERBOSE;
         break;
         case 'f':
            if (!strncmp(optarg, "max", 3))      wping.ping_func = tpf_max;
            else if (!strncmp(optarg, "avg", 3)) wping.ping_func = tpf_avg;
            else if (!strncmp(optarg, "min", 3)) wping.ping_func = tpf_min;
            else
            {
               fprintf(stderr, "Function '%s' is unknown.\n", optarg);
               usage(argv[0]);
               exit(EXIT_FAILURE);
            }
         break;
         case 'w':
            wping.opts     |= PING_OPT_NOSLEEP;
         break;
         case 'c':
            wping.count    = strtol(optarg, NULL, 0);
         break;
         case 's':
            wping.buf_sz   = strtol(optarg, NULL, 0);
          break;
         case 'W':
            wping.delay    = strtol(optarg, NULL, 0);
         break;
         case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
         break;
         default:
            fprintf(stderr, "Parameter '%c' is unknown.\n", opt);
            usage(argv[0]);
            exit(EXIT_FAILURE);
         break;
      }
   }

   if (optind >= argc)
   {
      usage(argv[0]);
      exit(EXIT_FAILURE);
   }

   wping.host     = argv[optind];
   wping.pattern  = "aaaaaaaaaaaaaaaa";
   if (!load_icmp_dll(&hndlICMP)) exit(EXIT_FAILURE);

   if (!init_network())
   {
      FreeLibrary((HMODULE)hndlICMP);
      return;
   }
   if (wping.opts & PING_OPT_AVAIL) printf("%d\n", (ping(&wping)) ? 1 : 0);
   else ping(&wping);

   WSACleanup();
	FreeLibrary((HMODULE)hndlICMP);
}

