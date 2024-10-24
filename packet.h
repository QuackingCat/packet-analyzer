#ifndef _packet_h
#define _packet_h

#include <stdio.h>


#define ERR_MEM 1 // out of memory


// the field in an header
typedef struct {
    char *name;  // the name of the field
    char *value; // the value of the field
} field;


// a named collection of fields
typedef struct {
    char *name;    // the protocol name
    int fc;        // the number of fields
    field *hdr; // the fields of the header
} layer;


// a list of layers
typedef struct _packet{
    int lc; // the number of layers
    layer *lys; // the layers of the packet
    
    // functions for adding stuff to the packets (if needed, should be
    // assigned by the creating program), acts like vtable.
    int (*newlyr)(struct _packet *pckt, char *layername);
    int (*addfld)(struct _packet *pckt, char *fname, char *fvalue);
} packet;


#endif