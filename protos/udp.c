#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "proto.h"


proto(pid_11) {
    char format[30];
    struct _header {
        uint16_t src;
        uint16_t trg;
        uint16_t len;
        uint16_t checksum;
    } __attribute__((packed)) *hdr = (struct _header *)raw;
    
    
    pckt->newlyr(pckt, "User Datagram Protocol");
    
    sprintf(format, "%d", FLIP_BYTES(hdr->src));
    pckt->addfld(pckt, "Source Port", format);
    
    sprintf(format, "%d", FLIP_BYTES(hdr->trg));
    pckt->addfld(pckt, "Target Port", format);
    
    sprintf(format, "%d", FLIP_BYTES(hdr->len));
    pckt->addfld(pckt, "Length", format);
    
    sprintf(format, "0x%04x", FLIP_BYTES(hdr->checksum));
    pckt->addfld(pckt, "Checksum", format);
    
    *next_proto = (char *)malloc(10 * sizeof(char));
    sprintf(*next_proto, "proto_raw");
    
    return raw + sizeof(struct _header);
}