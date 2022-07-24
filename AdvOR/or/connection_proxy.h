#ifndef _CONNECTION_PROXY_H
#define _CONNECTION_PROXY_H

int connection_proxy_connect(connection_t *conn,int ntlm);
int dir_proxy_connect(connection_t *conn,int ntlm);
int connection_read_proxy_handshake(connection_t *conn);
int dir_read_proxy_handshake(connection_t *conn);

#endif
