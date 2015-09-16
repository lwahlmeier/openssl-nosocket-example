#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static SSL_CTX* create_server() {
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_CTX* server_ctx = SSL_CTX_new(SSLv23_method());
  if(server_ctx == NULL) {
    printf("ERROR Making Server Context!!!\n");
    exit(1);
  }
//  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
//  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CERTIFICATE);
//  SSL_CONF_CTX_set_ssl_ctx(cctx, server_ctx);
  return server_ctx;

//  return server_ctx;
}


struct SSLClient {
  SSL* ssl;
  BIO* rio;
  BIO* wio;
};

static void printHex(const char* data, int length) {
  for(int i=0; i<length; i++) {
    printf("%X", data[i]);
  }
}

static void parseSSL(SSLClient *server, SSLClient *client) {
  char cnbuff[1024]; //Client network buffer (encrypted data)
  char snbuff[1024]; //Server network buffer (encrypted data)
  char cabuff[1024]; //Client app buffer (unencrypted data)
  char sabuff[1024]; //Server app buffer (unencrypted data)

  //Flush all buffers to zeros
  memset(cnbuff, 0, sizeof(cnbuff));
  memset(cabuff, 0, sizeof(cabuff));
  memset(snbuff, 0, sizeof(snbuff));
  memset(sabuff, 0, sizeof(sabuff));

  //Look for pending write data on the client for the server to read
  int cw = BIO_read(client->wio, cnbuff, sizeof(cnbuff)-1);
  //Look for pending write data on the server for the client to read
  int sw = BIO_read(server->wio, snbuff, sizeof(snbuff)-1);

  //while any data needs written to the other we loop.
  while(cw > 0 || sw > 0) {

    if(cw > 0) { //is there data in the clients write buffer for the server to get
      printf("client needs to Send:%d\n",cw);
      printf("client_encrypted: ");
      printHex(cnbuff, cw);
      printf("\n");
      int sr = BIO_write(server->rio, cnbuff, cw); //Write that data to the Server.
      memset(cnbuff, 0, sizeof(cnbuff));
      printf("client sent:%d\n",sr);
    }

    int ssr = SSL_read(server->ssl, sabuff, sizeof(sabuff)-1);  //Does the server have data to read/unencrypt from the client
    if(ssr > 0) {
      printf("server_ssl_read:%d\n",ssr);
      printf("server_unencrypted:%s\n",sabuff);
      memset(sabuff, 0, sizeof(sabuff));
    }
    if(sw > 0) { //Did the server have data to write to then client
      printf("server needs to Send:%d\n",sw);
      printf("server_encrypted:");
      printHex(snbuff, sw);
      printf("\n");
      int cr = BIO_write(client->rio, snbuff, sw); //Write that data to the client
      memset(snbuff, 0, sizeof(snbuff));
      printf("server_sent:%d\n",cr);
    }
    int csr = SSL_read(client->ssl, cabuff, sizeof(cabuff)-1); //Does the client have app data to read
    if(csr > 0) {
      printf("client_ssl_read:%d\n",csr);
      printf("client_unencrypted:%s\n",cabuff);
      memset(cabuff, 0, sizeof(cabuff));
    }
    //Check the write buffers of both connections again and see if more needs to be sent
    cw = BIO_read(client->wio, cnbuff, sizeof(cnbuff)-1);
    sw = BIO_read(server->wio, snbuff, sizeof(snbuff)-1);
  }
}



void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
  /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) {
      printf("Error loading certFile\n");
      exit(1);
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
      printf("Error loading keyFile\n");
      exit(1);
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) ) {
      printf("Error with Key\n");
      exit(1);
    }
}

int main(int argc, char *argv[]) {
  const char* file = "test.pem";
  SSLClient *c_state = new SSLClient();
  SSLClient *s_state = new SSLClient();
  SSL_load_error_strings();
  SSL_library_init();

  //Basic context for all SSL connections
  SSL_CTX* server_ctx = create_server();

  //Add Certs to connection (only required for SSL_accept)
  LoadCertificates(server_ctx, file, file);
    

  //Create an SSL stream for the server, as well as io buffers
  s_state->ssl = SSL_new(server_ctx);
  s_state->rio = BIO_new(BIO_s_mem());
  s_state->wio = BIO_new(BIO_s_mem());
  SSL_set_bio(s_state->ssl, s_state->rio, s_state->wio);


  //Create an SSL stream for the client as well as io buffers
  c_state->ssl = SSL_new(server_ctx);
  c_state->rio = BIO_new(BIO_s_mem());
  c_state->wio = BIO_new(BIO_s_mem());
  SSL_set_bio(c_state->ssl, c_state->rio, c_state->wio);


  //Tell the Server to accept ssl negotiation.
  SSL_accept(s_state->ssl);
  //Tell the Client to start negotiation.
  SSL_connect(c_state->ssl);

  //Do any need ssl work (handshake)
  parseSSL(s_state, c_state);
  
  char input[1024];
  while(true) {
    printf("What to Send: ");
    char *data = fgets(input, sizeof(input), stdin);
    printf("Sending: %s\n", data);
    //here we write plain txt to the Client
    SSL_write(c_state->ssl, data, strlen(data));
    //now send that data on to the Server
    parseSSL(s_state, c_state);
  }
  

}


