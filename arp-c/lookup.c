#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{

	struct hostent *he;
	struct in_addr *addr;

	if (2 != argc)
	 { 
	  printf("Usage: %s <hostname>\n", argv[0]);
	  exit(1);
	 }

	he = gethostbyname(argv[1]);
	if (he == NULL)
	{
	 perror("gethostbyname");
	 exit(1);
	}

	printf("Hostname: %s\n", argv[1]);
	printf("IP: %s\n", inet_ntoa(*((struct in_addr *)he->h_addr)));	

	return (0);
}	
