/*
Copyright (c) 2003-2006 by Juliusz Chroboczek

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

extern int serverExpireTime, dontCacheRedirects;

typedef struct _HTTPServer {
    char *name;
    int port;
    int addrindex;
    int isProxy;
    int version;
    int persistent;
    int pipeline;
    int lies;
    int rtt;
    int rate;
    time_t time;
    int numslots;
    int maxslots;
    HTTPConnectionPtr *connection;
    FdEventHandlerPtr *idleHandler;
    HTTPRequestPtr request, request_last;
    struct _HTTPServer *next;
} HTTPServerRec, *HTTPServerPtr;

extern AtomPtr parentHost;
extern int parentPort;

void preinitServer(void);
void initServer(void);

int  httpServerDoSide(HTTPConnectionPtr connection);
void httpServerClientReset(HTTPRequestPtr request);
int httpServerRequest(ObjectPtr object, int method, int from, int to,
                      HTTPRequestPtr, void*);
void listServers(FILE*);
