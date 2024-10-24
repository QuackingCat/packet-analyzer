#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include "packet.h"
#include "./protos/proto.h"


// functions for packets
static packet *allocpacket();
static int newlayer(packet *pckt, char *layername);
static int addfield(packet *pckt, char *fname, char *fvalue);
static void printpacket(FILE *stream, packet *pckt);
static void freepacket(packet *pckt);


#define PROTOCOLS_LIB "./protos.so"
//#define protocall("") (((*)())dlsym())()

int main(int argc, char **argv){
    int i;
    
    if (argc == 1) {
        printf("Usage: %s file1 [file2 ...]\n", argv[0]);
        return 1;
    }
    
    printf("Files to analyze:\n");
    for (i = 1; i < argc; i++){
        printf("%s\n", argv[i]);
    }
    
    /*
    i = 0;
    printf("Start? [y|n]: ");
    i = getchar();
    
    if (i != 'y' && i != 'Y'){
        return 0;
    }
    */
    
    // open the protocols library
    void *protos = dlopen(PROTOCOLS_LIB, RTLD_LAZY);
    if (protos == NULL){
        printf("Error: can't open %s\n", PROTOCOLS_LIB);
        return 1;
    }
    
    for (i = 1; i < argc; i++){
        // the analyzed packet
        packet *pckt = allocpacket();
        //if (pckt == NULL) return 1/0;
        
        size_t pcktsize; // the raw packet size
        char *raw; // the raw packet
        
        printf("\n%s:\n", argv[i]);
        
        // open the fist packet
        FILE *fp = fopen(argv[i], "rb"); 
        
        // check the packet size
        fseek(fp, 0L, SEEK_END);
        pcktsize = ftell(fp);
        rewind(fp);
        
        if (pcktsize == 0){
            printf("!!!empty file!!!\n");
            fclose(fp);
            continue;
        }
        
        raw = malloc(pcktsize * sizeof(char));

        //if (raw == NULL) return 1/0;
        
        fread(raw, sizeof(char), pcktsize, fp);
        fclose(fp);
        
        // !!!!!!!!!!!!!!!!!!!!!!!! assume Ethernet frame !!!!!!!!!!!!!!!!!!!!!!!!
        char *next = NULL, *payload = raw;
        do {
            #pragma GCC diagnostic ignored "-Wpedantic"
            proto_func pf = (proto_func)dlsym(protos, next == NULL ? "proto_ieee802_3" : next);
            #pragma GCC diagnostic pop
            if (pf == NULL) {
                break;
            }
            free(next);
            next = NULL;
            payload = pf(payload, pcktsize, pckt, &next);
        } while (next != NULL);
        if (next != NULL) {
            printpacket(stdout, pckt);
            printf("ERROR: unimplemented protocol \"%s\"\n", next);
            free(next);
        } else {
            printpacket(stdout, pckt);
        }
        
        freepacket(pckt);
        free(raw);
        dlclose(protos);
    }
    
    return 0;
}




static packet *allocpacket() {
    packet *pckt = (packet *)malloc(sizeof(packet));
    if (pckt == NULL) return NULL;
    
    pckt->lc = 0;
    pckt->lys = NULL;
    
    pckt->newlyr = newlayer;
    pckt->addfld = addfield;
    
    return pckt;
}

static int newlayer(packet *pckt, char *layername) {
    char *name = (char *)malloc(strlen(layername)*sizeof(char));
    if (name == NULL) {
        printf("(1) errno: %d\n", errno); 
        return ERR_MEM;
    }
    strcpy(name, layername);
    
    layer *lys = (layer *)reallocarray(pckt->lys, pckt->lc + 1, sizeof(layer));
    if (lys == NULL) {
        printf("(2) errno: %d\n", errno); 
        free(name);
        return ERR_MEM;
    }
    
    pckt->lys = lys;
    lys[pckt->lc].name = name;
    lys[pckt->lc].fc = 0;
    lys[pckt->lc].hdr = NULL;
    
    (pckt->lc)++;
    return 0;
}

static int addfield(packet *pckt, char *fname, char *fvalue) {
    layer *lyr = pckt->lys + (pckt->lc - 1);

    char *name = (char *)malloc(strlen(fname)*sizeof(char));
    if (name == NULL) {
        printf("(3) errno: %d\n", errno); 
        return ERR_MEM;
    }
    strcpy(name, fname);
    
    char *value = (char *)malloc(strlen(fvalue)*sizeof(char));
    if (value == NULL) {
        printf("(4) errno: %d\n", errno); 
        free(name);
        return ERR_MEM;
    }
    strcpy(value, fvalue);
    
    field *hdr = (field *)reallocarray(lyr->hdr, lyr->fc + 1, sizeof(field));
    if (hdr == NULL) {
        printf("(5) errno: %d\n", errno);
        free(name);
        free(value);
        return ERR_MEM;
    }
    
    lyr->hdr = hdr;
    hdr[lyr->fc].name = name;
    hdr[lyr->fc].value = value;
    
    (lyr->fc)++;
    return 0;
}

static void printfancy(FILE *stream, char *str) {
    if (str == NULL || *str == 0) return;
    
    for (; *str != 0; str++) {
        putc(*str, stream);
        if (*str == '\n') for (int i = 0; i < 20; i++) putc(' ', stream);
    }
    putc('\n', stream);
}

static void printpacket(FILE *stream, packet *pckt) {
    for (int i = 0; i < pckt->lc; i++) {
        layer *lyr = pckt->lys + i;
        fprintf(stream, "%d. %s\n%.*s\n", i+1, lyr->name, (int)strlen(lyr->name) + 3, "==============================");

        for (int j = 0; j < lyr->fc; j++) {
            field *fld = lyr->hdr + j;
            fprintf(stream, "%-20s", fld->name);
            printfancy(stream, fld->value);
        }
        putc('\n', stream);
    }
}

static void freepacket(packet *pckt) {
    for (int i = 0; i < pckt->lc; i++) {
        layer *lyr = pckt->lys + i;
        for (int j = 0; j < lyr->fc; j++) {
            field *fld = lyr->hdr + j;
            
            free(fld->name);
            free(fld->value);
            fld->name = NULL;
            fld->value = NULL;
        }

        free(lyr->name);
        free(lyr->hdr);
        lyr->name = NULL;
        lyr->fc = 0;
        lyr->hdr = NULL;
    }
    
    free(pckt->lys);
    pckt->lc = 0;
    pckt->lys = NULL;
    
    free(pckt);
}