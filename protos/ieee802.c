#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "proto.h"


// LLC
proto(ieee802_2) {
    char format[30];
    
    typedef struct {int lsap : 7; int lowbit : 1;} sap;
    struct _header1 {
        uint8_t dsap;
        uint8_t ssap;
        uint8_t ctrl;
    } *hdr = (struct _header1 *)raw;
    sap dsap = {.lowbit = hdr->dsap & 1u, .lsap = hdr->dsap >> 1u};
    sap ssap = {.lowbit = hdr->ssap & 1u, .lsap = hdr->ssap >> 1u};
    
    pckt->newlyr(pckt, "Logical Link Control");
    
    sprintf(format, "%s address - 0x%hhx", (dsap.lowbit&1 ? "Group" : "Individual"), dsap.lsap&0x7f);
    pckt->addfld(pckt, "DSAP", format);
    
    sprintf(format, "Address - 0x%hhx\n%s", ssap.lsap&0x7f, (ssap.lowbit&1 ? "Response" : "Command"));
    pckt->addfld(pckt, "SSAP", format);
    
    
    if (!(hdr->dsap == 0xAA && hdr->ssap == 0xAA && hdr->ctrl == 3)) {
        pckt->addfld(pckt, "Error", "Unimplemented case");
        *next_proto = NULL;
        return NULL;
    }
    
    // not my problem
    sprintf(format, "Unnumbered Information (0x03)");
    pckt->addfld(pckt, "Control", format);
    
    raw = raw + sizeof(struct _header1);
    
    // SNAP handling
    struct _header2 {
        char oui[3];
        uint16_t ether;
    } __attribute__((packed)) *hdrsnap = (struct _header2 *)raw;
    int ethertype = FLIP_BYTES(hdrsnap->ether);
    
    sprintf(format, "%02hhx:%02hhx:%02hhx", hdrsnap->oui[0], hdrsnap->oui[1], hdrsnap->oui[2]);
    pckt->addfld(pckt, "SNAP OUI", format);
    
    sprintf(format, "0x%04x", ethertype);
    pckt->addfld(pckt, "Type"  , format);
    
    
    if (hdrsnap->oui[0] != 0 || hdrsnap->oui[1] != 0 || hdrsnap->oui[2] != 0) {
        pckt->addfld(pckt, "Error"  , "Unknown Type per given OUI");
        *next_proto = NULL;
        return NULL;
    }
    
    *next_proto = (char *)malloc(21 * sizeof(char));
    sprintf(*next_proto, "proto_ethertype_%04x", ethertype);
    
    return raw + sizeof(struct _header2);
}
duproto(ieee802_2, ethertype_8870)


// Ethernet
proto(ieee802_3) {
    static char *NAMES[] = {"IEEE 802.3 Ethernet", "Ethernet II"};
    int ethernet;
    char format[30];
    struct _header {
        char trg[6];
        char src[6];
        uint16_t ether;
    } *hdr = (struct _header *)raw;
    int ethertype = FLIP_BYTES(hdr->ether);
    
    if (ethertype < 1536) { // "IEEE 802.3 Ethernet"
        ethernet = 0;
        *next_proto = (char *)malloc(16 * sizeof(char));
        sprintf(*next_proto, "proto_IEEE802_2"); // LLC
    } else { // "Ethernet II"
        ethernet = 1;
        *next_proto = (char *)malloc(21 * sizeof(char));
        sprintf(*next_proto, "proto_ethertype_%04x", ethertype);
    }
    
    pckt->newlyr(pckt, NAMES[ethernet]);
    
    sprintf(format, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", hdr->trg[0], hdr->trg[1], hdr->trg[2], hdr->trg[3], hdr->trg[4], hdr->trg[5]);
    pckt->addfld(pckt, "Target", format);
    
    sprintf(format, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", hdr->src[0], hdr->src[1], hdr->src[2], hdr->src[3], hdr->src[4], hdr->src[5]);
    pckt->addfld(pckt, "Source", format);
    
    switch (ethernet) {
        case 0:
            sprintf(format, "%d", ethertype);
            pckt->addfld(pckt, "Length", format);
            break;
        case 1:
            sprintf(format, "0x%04x", ethertype);
            pckt->addfld(pckt, "Type"  , format);
            break;
    }
    
    return raw + 14;
}
duproto(ieee802_3, pid_8f)