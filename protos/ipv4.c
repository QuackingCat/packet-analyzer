#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "proto.h"

static const char *ECN_TYPES[] = {"Not ECT", "ECT(1)", "ECT(0)", "CE"};
static const char *FLAG_TYPES[] = {"R", "DF", "MF"};

proto(ethertype_0800) {
    char format[30];
    struct _header{
        int headsize : 4; // 5...15 ==> 20...60 bytes
        int version  : 4; 
        int ecn      : 2;
        int dscp     : 6;
        uint16_t len;
        char ident[2];
        int fragoffs1 :5;
        int flags     :3;
        char fragoffs2;
        char ttl;
        char nextproto;
        char checksum[2];
        char source[4];
        char target[4];
    } *hdr = (struct _header *)raw;
    
    pckt->newlyr(pckt, "Internet Protocol v4");

    sprintf(format, "%d", hdr->version);
    pckt->addfld(pckt, "Version", format);

    sprintf(format, "%d bytes", hdr->headsize * 4);
    pckt->addfld(pckt, "Header Size", format);

    sprintf(format, "CS%d", hdr->dscp); // more options
    pckt->addfld(pckt, "DSCP", format);

    sprintf(format, "%d - %s", hdr->ecn, ECN_TYPES[hdr->ecn]);
    pckt->addfld(pckt, "ECN", format);

    sprintf(format, "%d bytes", FLIP_BYTES(hdr->len));
    pckt->addfld(pckt, "Packet Size", format);

    sprintf(format, "0x%02hhx%02hhx", hdr->ident[0], hdr->ident[1]);
    pckt->addfld(pckt, "Identification", format);

    sprintf(format, "%d - %s", hdr->flags, FLAG_TYPES[hdr->flags]);
    pckt->addfld(pckt, "Flags", format);
    
    union {
        int value;
        struct {
            int frag2 : 8;
            int frag1 : 5;
            int zero  : 3;
        } parts;
    } fragoffs = {.parts.frag1 = hdr->fragoffs1, .parts.frag2 = hdr->fragoffs2};
    sprintf(format, "%u", fragoffs.value * 8);
    pckt->addfld(pckt, "Fragment Offse", format);

    sprintf(format, "%hhu", hdr->ttl);
    pckt->addfld(pckt, "Time To Live", format);

    sprintf(format, "0x%02hhx", hdr->nextproto); // maybe add protocol name
    pckt->addfld(pckt, "Protocol", format);
    
    sprintf(format, "0x%02hhx%02hhx", hdr->checksum[0], hdr->checksum[1]);
    pckt->addfld(pckt, "Checksum", format);

    sprintf(format, "%hhu.%hhu.%hhu.%hhu", hdr->source[0], hdr->source[1], hdr->source[2], hdr->source[3]);
    pckt->addfld(pckt, "Source", format);

    sprintf(format, "%hhu.%hhu.%hhu.%hhu", hdr->target[0], hdr->target[1], hdr->target[2], hdr->target[3]);
    pckt->addfld(pckt, "Target", format);
    
    
    // optional header not handled
    
    
    sprintf(format, "proto_pid_%02hhx", hdr->nextproto);
    *next_proto = malloc(strlen(format)*sizeof(char));
    strcpy(*next_proto, format);
    return raw + hdr->headsize * 4;
}
duproto(ethertype_0800, pid_04)