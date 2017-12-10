#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libwebsockets.h>

static int callback_http(
    struct libwebsocket_context *context,
    struct libwebsocket *wsi,
    enum libwebsocket_callback_reasons reason,
    void *user,
    void *in, size_t len
) {
  switch (reason) {
    // http://git.warmcat.com/cgi-bin/cgit/libwebsockets/tree/lib/libwebsockets.h#n260
    case LWS_CALLBACK_CLIENT_WRITEABLE:
      printf("connection established\n");
           
      // http://git.warmcat.com/cgi-bin/cgit/libwebsockets/tree/lib/libwebsockets.h#n281
    case LWS_CALLBACK_HTTP: {
      char *requested_uri = (char *) in;
      printf("requested URI: %s\n", requested_uri);
           
      if (strcmp(requested_uri, "/") == 0) {
        void *universal_response = "Hello, World!";
        // http://git.warmcat.com/cgi-bin/cgit/libwebsockets/tree/lib/libwebsockets.h#n597
        libwebsocket_write(wsi, universal_response,
            strlen(universal_response), LWS_WRITE_HTTP);
        break;

        } else {
          // try to get current working directory
          char cwd[1024];
          char *resource_path;
               
          if (getcwd(cwd, sizeof(cwd)) != NULL) {
            // allocate enough memory for the resource path
            resource_path = malloc(strlen(cwd)
                + strlen(requested_uri));
                   
            // join current working directory to the resource path
            sprintf(resource_path, "%s%s", cwd, requested_uri);
            printf("resource path: %s\n", resource_path);
                   
            char *extension = strrchr(resource_path, '.');
            char *mime;
                   
            // choose mime type based on the file extension
            if (extension == NULL) {
              mime = "text/plain";
            } else if (strcmp(extension, ".png") == 0) {
              mime = "image/png";
            } else if (strcmp(extension, ".jpg") == 0) {
              mime = "image/jpg";
            } else if (strcmp(extension, ".gif") == 0) {
              mime = "image/gif";
            } else if (strcmp(extension, ".html") == 0) {
              mime = "text/html";
            } else if (strcmp(extension, ".css") == 0) {
              mime = "text/css";
            } else {
              mime = "text/plain";
            }
                   
            // by default non existing resources return code 400
            // for more information how this function handles 
            // headers see it's source code
            // http://git.warmcat.com/cgi-bin/cgit/libwebsockets/tree/lib/parsers.c#n1896
            libwebsockets_serve_http_file(wsi, resource_path, mime);
                   
          }
        }
           
        // close connection
        libwebsocket_close_and_free_session(
            context, wsi, LWS_CLOSE_STATUS_NORMAL);
        break;
      }
      default:
        printf("unhandled callback\n");
        break;
  }
   
  return 0;
}