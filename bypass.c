/*
Copyright (c) 2003-2010 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "polipo.h"

#ifndef NO_BYPASS

#include <regex.h>
#include <assert.h>

typedef struct _Domain {
    int length;
    char domain[1];
} DomainRec, *DomainPtr;

AtomPtr bypassFile = NULL;
AtomPtr bypassUrl = NULL;

DomainPtr *bypassDomains = NULL;
regex_t *bypassRegex = NULL;

AtomPtr bypassTunnelsFile = NULL;
DomainPtr *bypassTunnelsDomains = NULL;
regex_t *bypassTunnelsRegex = NULL;


/* these three are only used internally by {parse,read}DomainFile */
/* to avoid having to pass it all as parameters */
//static DomainPtr *domains;
//static char *regexbuf;
//static int rlen, rsize, dlen, dsize;

static int atomSetterBypass(ConfigVariablePtr, void*);

void
preinitBypass(void)
{
    CONFIG_VARIABLE_SETTABLE(bypassFile, CONFIG_ATOM, atomSetterBypass,
                             "File specifying bypass URLs.");
    CONFIG_VARIABLE_SETTABLE(bypassTunnelsFile, CONFIG_ATOM, atomSetterBypass,
                             "File specifying bypass tunnels.");
}

static int
atomSetterBypass(ConfigVariablePtr var, void *value)
{
    initBypass();
    return configAtomSetter(var, value);
}

void
parseDomainFile(AtomPtr file,
                DomainPtr **domains_return, regex_t **regex_return);

void
initBypass(void)
{
    //redirectorKill();

    if(bypassFile)
        bypassFile = expandTilde(bypassFile);

    if(bypassFile == NULL) {
        bypassFile = expandTilde(internAtom("~/.polipo-bypass"));
        if(bypassFile) {
            if(access(bypassFile->string, F_OK) < 0) {
                releaseAtom(bypassFile);
                bypassFile = NULL;
            }
        }
    }

    if(bypassFile == NULL) {
        if(access("/etc/polipo/bypass", F_OK) >= 0)
            bypassFile = internAtom("/etc/polipo/bypass");
    }

    parseDomainFile(bypassFile, &bypassDomains, &bypassRegex);


    if(bypassTunnelsFile)
        bypassTunnelsFile = expandTilde(bypassTunnelsFile);
    
    if(bypassTunnelsFile == NULL) {
        bypassTunnelsFile = expandTilde(internAtom("~/.polipo-bypassTunnels"));
        if(bypassTunnelsFile) {
            if(access(bypassTunnelsFile->string, F_OK) < 0) {
                releaseAtom(bypassTunnelsFile);
                bypassTunnelsFile = NULL;
            }
        }
    }
    
    if(bypassTunnelsFile == NULL) {
        if(access("/etc/polipo/bypassTunnels", F_OK) >= 0)
            bypassTunnelsFile = internAtom("/etc/polipo/bypassTunnels");
    }
    
    parseDomainFile(bypassTunnelsFile, &bypassTunnelsDomains, &bypassTunnelsRegex);
    
    return;
}

int
hostNameIsBypassed(char *name) {
    int i = strlen(name);
    DomainPtr *domain;

    domain = bypassDomains;
    if (domain) {
        while(*domain) {
            if((*domain)->length <= i  &&
               (name[i - (*domain)->length - 1] == '.' ||
                name[i - (*domain)->length - 1] == '/') &&
               memcmp(name + i - (*domain)->length,
                      (*domain)->domain,
                      (*domain)->length) == 0)
                return 1;
            domain++;
        }
    }

    if(bypassRegex)
        return !regexec(bypassRegex, name, 0, NULL, 0);

    return 0;
}

#else


void
preinitBypass()
{
    return;
}

void
initBypass()
{
    return;
}


int
hostNameIsBypassed(char *name) {
    return 0;
}
#endif
