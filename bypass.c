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
int bypassRedirectCode = 302;

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

#ifndef NO_REDIRECTOR
//static pid_t redirector_pid = 0;
//static int redirector_read_fd = -1, redirector_write_fd = -1;
#define REDIRECTOR_BUFFER_SIZE 1024
//static char *redirector_buffer = NULL;
//RedirectRequestPtr redirector_request_first = NULL,
//    redirector_request_last = NULL;
#endif

static int atomSetterBypass(ConfigVariablePtr, void*);

void
preinitBypass(void)
{
    CONFIG_VARIABLE_SETTABLE(bypassUrl, CONFIG_ATOM, configAtomSetter,
                             "URL to which bypass requests "
                             "should be redirected.");
    CONFIG_VARIABLE_SETTABLE(bypassRedirectCode, CONFIG_INT,
                             configIntSetter,
                             "Redirect code, 301 or 302.");
    CONFIG_VARIABLE_SETTABLE(bypassFile, CONFIG_ATOM, atomSetterBypass,
                             "File specifying bypass URLs.");
#ifndef NO_REDIRECTOR
    //CONFIG_VARIABLE_SETTABLE(redirector, CONFIG_ATOM, atomSetterBypass,
    //                         "Squid-style redirector.");
    //CONFIG_VARIABLE_SETTABLE(redirectorRedirectCode, CONFIG_INT,
    //                         configIntSetter,
    //                         "Redirect code to use with redirector.");
#endif
    CONFIG_VARIABLE_SETTABLE(bypassTunnelsFile, CONFIG_ATOM, atomSetterBypass,
                             "File specifying bypass tunnels.");
}

static int
atomSetterBypass(ConfigVariablePtr var, void *value)
{
    initBypass();
    return configAtomSetter(var, value);
}
/*
int
readDomainFile(char *filename)
{
    FILE *in;
    char buf[512];
    char *rs;
    int i, j, is_regex, start;

    in = fopen(filename, "r");
    if(in == NULL) {
        if(errno != ENOENT)
            do_log_error(L_ERROR, errno, "Couldn't open file %s", filename);
        return -1;
    }

    while(1) {
        rs = fgets(buf, 512, in);
        if(rs == NULL)
            break;
        for(i = 0; i < 512; i++) {
            if(buf[i] != ' ' && buf[i] != '\t')
                break;
        }
        start = i;
        for(i = start; i < 512; i++) {
            if(buf[i] == '#' || buf[i] == '\r' || buf[i] == '\n')
                break;
        }
        while(i > start) {
            if(buf[i - 1] != ' ' && buf[i - 1] != '\t')
                break;
            i--;
        }

        if(i <= start)
            continue;


        is_regex = 0;
        for(j = start; j < i; j++) {
            if(buf[j] == '\\' || buf[j] == '*' || buf[j] == '/') {
                is_regex = 1;
                break;
            }
        }

        if(is_regex) {
            while(rlen + i - start + 8 >= rsize) {
                char *new_regexbuf;
                new_regexbuf = realloc(regexbuf, rsize * 2 + 1);
                if(new_regexbuf == NULL) {
                    do_log(L_ERROR, "Couldn't reallocate regex.\n");
                    fclose(in);
                    return -1;
                }
                regexbuf = new_regexbuf;
                rsize = rsize * 2 + 1;
            }
            if(rlen != 0)
                rlen = snnprintf(regexbuf, rlen, rsize, "|");
            rlen = snnprintf(regexbuf, rlen, rsize, "(");
            rlen = snnprint_n(regexbuf, rlen, rsize, buf + start, i - start);
            rlen = snnprintf(regexbuf, rlen, rsize, ")");
        } else {
            DomainPtr new_domain;
            if(dlen >= dsize - 1) {
                DomainPtr *new_domains;
                new_domains = realloc(domains, (dsize * 2 + 1) *
                                      sizeof(DomainPtr));
                if(new_domains == NULL) {
                    do_log(L_ERROR,
                           "Couldn't reallocate domain list.\n");
                    fclose(in);
                    return -1;
                }
                domains = new_domains;
                dsize = dsize * 2 + 1;
            }
            new_domain = malloc(sizeof(DomainRec) - 1 + i - start);
            if(new_domain == NULL) {
                do_log(L_ERROR, "Couldn't allocate domain.\n");
                fclose(in);
                return -1;
            }
            new_domain->length = i - start;
            memcpy(new_domain->domain, buf + start, i - start);
            domains[dlen++] = new_domain;
        }
    }
    fclose(in);
    return 1;
}
*/

void
parseDomainFile(AtomPtr file,
                DomainPtr **domains_return, regex_t **regex_return);
/*
{
    struct stat ss;
    regex_t *regex;
    int rc;

    if(*domains_return) {
        DomainPtr *domain = *domains_return;
        while(*domain) {
            free(*domain);
            domain++;
        }
        free(*domains_return);
        *domains_return = NULL;
    }

    if(*regex_return) {
        regfree(*regex_return);
        *regex_return = NULL;
    }

    if(!file || file->length == 0)
        return;

    domains = malloc(64 * sizeof(DomainPtr));
    if(domains == NULL) {
        do_log(L_ERROR, "Couldn't allocate domain list.\n");
        return;
    }
    dlen = 0;
    dsize = 64;

    regexbuf = malloc(512);
    if(regexbuf == NULL) {
        do_log(L_ERROR, "Couldn't allocate regex.\n");
        free(domains);
        return;
    }
    rlen = 0;
    rsize = 512;

    rc = stat(file->string, &ss);
    if(rc < 0) {
        if(errno != ENOENT)
            do_log_error(L_WARN, errno, "Couldn't stat file %s", file->string);
    } else {
        if(!S_ISDIR(ss.st_mode))
            readDomainFile(file->string);
        else {
            char *fts_argv[2];
            FTS *fts;
            FTSENT *fe;
            fts_argv[0] = file->string;
            fts_argv[1] = NULL;
            fts = fts_open(fts_argv, FTS_LOGICAL, NULL);
            if(fts) {
                while(1) {
                    fe = fts_read(fts);
                    if(!fe) break;
                    if(fe->fts_info != FTS_D && fe->fts_info != FTS_DP &&
                       fe->fts_info != FTS_DC && fe->fts_info != FTS_DNR)
                        readDomainFile(fe->fts_accpath);
                }
                fts_close(fts);
            } else {
                do_log_error(L_ERROR, errno,
                             "Couldn't scan directory %s", file->string);
            }
        }
    }

    if(dlen > 0) {
        domains[dlen] = NULL;
    } else {
        free(domains);
        domains = NULL;
    }

    if(rlen > 0) {
        regex = malloc(sizeof(regex_t));
        rc = regcomp(regex, regexbuf, REG_EXTENDED | REG_NOSUB);
        if(rc != 0) {
            char errbuf[100];
            regerror(rc, regex, errbuf, 100);
            do_log(L_ERROR, "Couldn't compile regex: %s.\n", errbuf);
            free(regex);
            regex = NULL;
        }
    } else {
        regex = NULL;
    }
    free(regexbuf);

    *domains_return = domains;
    *regex_return = regex;

    return;
}
*/

void
initBypass(void)
{
    redirectorKill();

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


//int
//urlIsMatched(char *url, int length, DomainPtr *domains, regex_t *regex);
//{
    /* This requires url to be NUL-terminated. */
/*
    assert(url[length] == '\0');

    if(length < 8)
        return 0;

    if(lwrcmp(url, "http://", 7) != 0)
        return 0;

    if(domains) {
        int i;
        DomainPtr *domain;
        for(i = 8; i < length; i++) {
            if(url[i] == '/')
                break;
        }
        domain = domains;
        while(*domain) {
            if((*domain)->length <= (i - 7) &&
               (url[i - (*domain)->length - 1] == '.' ||
                url[i - (*domain)->length - 1] == '/') &&
               memcmp(url + i - (*domain)->length,
                      (*domain)->domain,
                      (*domain)->length) == 0)
                return 1;
            domain++;
        }
    }

    if(regex)
        return !regexec(regex, url, 0, NULL, 0);

    return 0;
}
*/

int
hostNameIsBypassed(char *name) {
    int i = strlen(name);
    DomainPtr *domain;

    domain = bypassDomains;
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
