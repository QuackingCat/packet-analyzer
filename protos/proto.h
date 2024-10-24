#include <stdint.h> // size_t
#include "../packet.h"

// flip the upper and lower bytes
#define FLIP_BYTES(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))


/* the identifying name of the protocol.
 * the first part is the an identifying list, example:
 * protocols implementing ieee802 would be
 * Ethernet - proto(ieee802_3)
 * WIFI     - proto(ieee802_11)
 * 
 * for layer over IP
 * ICMP - proto(pid_01)
 * TCP  - proto(pid_06)
 * ICMP for IPv6 - proto(pid_3A)
 *
 * parameters:
 * raw - the input buffer for the current layer
 * rlen - the length of the buffer
 * pckt - the packet to add the information to
 * next_proto - the next protocol that should process the packet or file type for 
 *              payload, if NULL then the processing stops.
 * 
 * return:
 * a pointer to the start of the payload or header of the next layer
 *  
 * note:
 * if a protocol has more than one identifing name (like capsulation) one name should reference the other.
 * the function is responsible to adding the current layer and fields to the "pckt"
 * parameter using the methods "newlyr" and "addfld".
 * examples for "next_proto",
 * .txt, .html, .bin, NULL, pid_143, pid_6, ethertype_2048.
 * !!!!next_proto should be freed to prevent memoey leaks!!!!
 */
#define proto(name) char * proto_ ## name (char *raw, size_t rlen, packet *pckt, char **next_proto)
#define duproto(name, newalias) proto(newalias) {return proto_ ## name (raw, rlen, pckt, next_proto);}

typedef char * (*proto_func)(char *raw, size_t rlen, packet *pckt, char **next_proto);