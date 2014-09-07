// libpcap_interfaces.cpp : Defines the entry point for the console application.
//

// windows stuff here
#include "stdafx.h"


/*
 * \author	Piotr Gregor
 *
 * \brief	Libpcap introduction
 *			Lookup the interface, list the network ip
 *			and mask associated with that interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>

// windows stuff here
#include <inaddr.h>

int main(int argc, char **argv)
{
  PCSTR dev; /* name of the device to use */
  PCSTR net; /* dot notation of the network address */
  PCSTR mask;/* dot notation of the network mask    */
  int ret;   /* return code */
  TCHAR errbuf[ PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp; /* ip          */
  bpf_u_int32 maskp;/* subnet mask */
  struct in_addr addr;

  /* ask pcap to find a valid device for use to sniff on */
  dev = pcap_lookupdev( (char*)errbuf);

  /* error checking */
  if (dev == NULL)
  {
   printf( "%s\n",errbuf);
   exit(1);
  }

  /* print out device name */
  printf( "DEV: %s\n",dev);

  /* ask pcap for the network address and mask of the device */
  ret = pcap_lookupnet( dev, &netp, &maskp , (char*)errbuf);

  if( ret == -1)
  {
   printf( "%s\n",errbuf);
   exit(1);
  }

  /* get the network address in a human readable form */
  addr.s_addr = netp;
  char inAddr[ INET_ADDRSTRLEN];
  net = inet_ntop( AF_INET, &addr, inAddr, INET_ADDRSTRLEN);

  if( net == NULL)/* thanks Scott :-P */
  {
    perror( "inet_ntop");
    exit(1);
  }

  printf( "NET: %s\n",net);

  /* do the same as above for the device's mask */
  memset( &inAddr, 0, sizeof inAddr);
  addr.s_addr = maskp;
  mask = inet_ntop( AF_INET, &addr, inAddr, INET_ADDRSTRLEN);
  
  if( mask == NULL)
  {
    perror( "inet_ntop");
    exit(1);
  }
  
  printf( "MASK: %s\n",mask);

  return 0;
}