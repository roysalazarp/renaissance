#include <argon2.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libpq-fe.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <regex.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <uuid/uuid.h>

/*
+-----------------------------------------------------------------------------------+
|                                     defines                                       |
+-----------------------------------------------------------------------------------+
*/

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

#define N0 0
#define N1 1
#define N2 2
#define N3 3
#define N4 4
#define N5 5
#define N6 6
#define N7 7
#define N8 8
#define N9 9
#define N10 10

#define ENV_FILE_PATH "./.env"

#define MAX_PATH_LENGTH 300
#define MAX_FILES 20
#define MAX_CLIENT_CONNECTIONS 100 /** ?? */
#define CONNECTION_POOL_SIZE 5

#define KB(value) ((value) * 1024)
#define PAGE_SIZE KB(4)

#define MAX_EVENTS 10 /** ?? */

#define BLOCK_EXECUTION -1 /* In the context of epoll this puts the process to sleep. */

#define COMPONENT_DEFINITION_OPENING_TAG__START "<x-component-def name=\""
#define COMPONENT_DEFINITION_OPENING_TAG__END "\">"
#define COMPONENT_IMPORT_OPENING_TAG__START "<x-component name=\""
#define OPENING_COMPONENT_IMPORT_TAG_SELF_CLOSING_END "\" />"
#define COMPONENT_IMPORT_OPENING_TAG__END "\">"
#define COMPONENT_DEFINITION_CLOSING_TAG "</x-component-def>"
#define COMPONENT_IMPORT_CLOSING_TAG "</x-component>"
#define TEMPLATE_OPENING_TAG "<x-template>"
#define TEMPLATE_CLOSING_TAG "</x-template>"
#define SLOT_TAG "<x-slot />"

#define FOR_OPENING_TAG__START "<x-for name=\""
#define FOR_OPENING_TAG__END "\">"
#define FOR_CLOSING_TAG "</x-for>"

#define VAL_OPENING_TAG__START "<x-val name=\""
#define VAL_SELF_CLOSING_TAG__END "\" />"

#define URL(path) path "\x20"
#define URL_WITH_QUERY(path) path "?"

#define HASH_LENGTH 32
#define SALT_LENGTH 16
#define PASSWORD_BUFFER 255 /** Do I need this ??? */

#define BINARY N1
#define TEXT N0

#define N1_PARAMS N1
#define N2_PARAMS N2
#define N3_PARAMS N3
#define N4_PARAMS N4
#define N5_PARAMS N5
#define N6_PARAMS N6
#define N7_PARAMS N7
#define N8_PARAMS N8
#define N9_PARAMS N9
#define N10_PARAMS N10

/**
 * NOTE: Implement a regular expression for email validation that adheres
 * to the RFC 5322 Official Standard. Using RFC 5322 regex as shown in
 * https://emailregex.com causes regcomp to throw error code 13.
 *
 * For now we just use a basic regex email validation
 */
#define EMAIL_REGEX "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"

/*
+-----------------------------------------------------------------------------------+
|                                     structs                                       |
+-----------------------------------------------------------------------------------+
*/

typedef int boolean;
#define true N1
#define false N0

typedef char uuid_str_t[37];

typedef enum { SERVER_SOCKET, CLIENT_SOCKET, DB_SOCKET } FDType;

typedef struct {
    FDType type; /** This need to be the first element in the struct */
    int fd;
} Socket;

typedef struct {
    size_t size;
    void *start;
    void *current;
} Arena;

typedef struct {
    char *start_addr;
    size_t length;
} String;

typedef struct {
    char *start_addr;
    char *end_addr;
} CharsBlock;

typedef CharsBlock Dict;        /** { 'k', 'e', 'y', '\0', 'v', 'a', 'l', 'u', 'e', '\0' ... } */
typedef CharsBlock StringArray; /** { 'f', 'o', 'o', '\0', 'b', 'a', 'r', '\0', 'b', 'a', 'z', '\0' ... } */
typedef CharsBlock TagLocation;

typedef CharsBlock User;

typedef struct {
    TagLocation opening_tag;
    TagLocation closing_tag;
} BlockLocation;

typedef struct {
    Socket *socket;
    Dict public_files_dict;
    Dict templates;
} GlobalArenaDataLookup;

typedef struct {
    Arena *arena;
    int client_socket;
    char *request;
} ScratchArenaDataLookup;

typedef struct {
    int fd;
    ScratchArenaDataLookup *scratch_arena_data;
    jmp_buf jmp_buf;
    uint8_t queued;
} Client;

typedef struct {
    FDType type; /** This need to be the first element in the struct */
    uint8_t index;
    PGconn *conn;
    Client client;
} DBConnection;

typedef struct {
    uint8_t index;
    Client client;
} QueuedRequest;

typedef struct {
    PGresult *result;
    DBConnection *connection;
} DBQueryCtx;

/*
+-----------------------------------------------------------------------------------+
|                               function declaration                                |
+-----------------------------------------------------------------------------------+
*/

/** Server setup */

Socket *create_server_socket(uint16_t port);

/** Arena */

Arena *arena_init(size_t size);
void *arena_alloc(Arena *arena, size_t size);
void arena_free(Arena *arena);
void arena_reset(Arena *arena, size_t arena_header_size);

/** Template engine */

Dict load_public_files(const char *base_path);
Dict load_html_components(const char *base_path);
Dict load_templates(const char *base_path);
void resolve_slots(char *component_markdown, char *import_statement, char **templates);
BlockLocation find_block(char *template, char *block_name);
size_t render_val(char *template, char *val_name, char *value);
size_t render_for(char *template, char *scope, int times, ...);
size_t replace_val(char *template, char *value_name, char *value);
size_t html_minify(char *buffer, char *html, size_t html_length);

/** Connection */

void create_connection_pool(Dict envs);
DBConnection *get_available_connection(Arena *scratch_arena_raw);
DBQueryCtx WPQsendQueryParams(DBConnection *connection, const char *command, int nParams, const Oid *paramTypes, const char *const *paramValues, const int *paramLengths, const int *paramFormats, int resultFormat);
PGresult *get_result(DBConnection *connection);
void print_query_result(PGresult *query_result);

/** Request handlers */

void router(Arena *scratch_arena_raw);
void public_get(Arena *scratch_arena_raw, String url);
void view_get(Arena *scratch_arena_raw, char *view, boolean accepts_query_params);
void test_get(Arena *scratch_arena_raw);
void home_get(Arena *scratch_arena_raw);
void auth_validate_email_post(Arena *scratch_arena_raw);
void register_create_account_post(Arena *scratch_arena_raw);
void login_create_session_post(Arena *scratch_arena_raw);
void release_request_resources_and_exit(Arena *scratch_arena_raw, DBConnection *connection);

/** Request utils */

String find_http_request_value(const char key[], char *request);
String find_body(const char *request);
String find_body_value(const char key[], String body);
char *file_content_type(Arena *scratch_arena_raw, const char *path);
char char_to_hex(unsigned char nibble); /** TODO: Review this function */
char hex_to_char(unsigned char c);      /** TODO: Review this function */
size_t url_encode_utf8(char **string, size_t length);
size_t url_decode_utf8(char **string, size_t length);
Dict parse_and_decode_params(Arena *scratch_arena_raw, String raw_query_params);
String find_cookie_value(const char *key, String cookies);
User is_authenticated(Arena *scratch_arena_raw, DBConnection *connection);

/** Utils */

Dict load_env_variables(const char *filepath);
void read_file(char **buffer, long *file_size, const char *absolute_file_path);
char *locate_files(char *buffer, const char *base_path, const char *extension, uint8_t level, uint8_t *total_html_files, size_t *all_paths_length);
char *find_value(const char key[], Dict dict);
int generate_salt(uint8_t *salt, size_t salt_size);
uint8_t get_dict_size(Dict dict);
void sigint_handler(int signo);
void dump_dict(Dict dict, char folder_name[]);

typedef struct {
    void *stack_ptr;
    size_t stack_size;
    char *stack_buffer;
} Stack;

void save_stack_state(Stack stack);
void restore_stack_state(Stack stack);

#define DECLARE_STACK_MARKER char __top__ = 't'

#define SAVE_STACK_STATE(stack)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        \
    do {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               \
        char __bottom__ = 'b';                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \
        stack.stack_size = (size_t) & __top__ - (size_t) & __bottom__;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 \
        stack.stack_ptr = (void *)&__top__;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            \
        save_stack_state(stack);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       \
    } while (0);

#define RESTORE_STACK_STATE(stack, result, expr)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       \
    do {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               \
        SAVE_STACK_STATE(stack);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       \
        result = (expr);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               \
        restore_stack_state(stack);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    \
    } while (0);

/*
+-----------------------------------------------------------------------------------+
|                                     globals                                       |
+-----------------------------------------------------------------------------------+
*/

volatile sig_atomic_t keep_running = 1;

Arena *_p_global_arena_raw;
GlobalArenaDataLookup *_p_global_arena_data;

int epoll_fd;
int nfds;
struct epoll_event events[MAX_EVENTS];
struct epoll_event event;

/**
 * Explanation of the use of setjmp and longjmp:
 *
 * - setjmp and longjmp are C functions used for non-local jumps. They allow
 *   jumping back to a previously saved program state, bypassing normal control flow.
 * - setjmp saves the program's state into a jmp_buf and returns 0 when called directly.
 * - longjmp restores the program's state saved by setjmp and makes it return a
 *   non-zero value, specified by the second argument of longjmp.
 *
 * The Problem:
 * - When longjmp is called, it must pass a non-zero integer (__val) as the second
 *   argument. If longjmp passes 0, setjmp cannot distinguish it from its initial
 *   return value (0).
 * - In this code, we need to pass a value (e.g., the index of a database connection)
 *   through longjmp. Sometimes the value is 0, but longjmp cannot directly pass 0
 *   due to the restriction above.
 *
 * The Hack (Workaround):
 * - To address this, the code adjusts the value using macros:
 *   - `to_index(i)`: Adds 1 to the original index (`i`) before passing it to longjmp.
 *     This ensures that 0 becomes 1, and other values are incremented similarly.
 *   - `from_index(i)`: Subtracts 1 to restore the original index. When the value is
 *     retrieved after longjmp, it is adjusted back to the correct value.
 * - This ensures that longjmp never passes 0, while the program can still use 0
 *   as a valid index internally.
 */
#define to_index(i) (i + 1)
#define from_index(i) (i - 1)

DBConnection connection_pool[CONNECTION_POOL_SIZE];
QueuedRequest queue[MAX_CLIENT_CONNECTIONS];

jmp_buf ctx;
jmp_buf db_ctx;

/*
+-----------------------------------------------------------------------------------+
|                                       code                                        |
+-----------------------------------------------------------------------------------+
*/

int main() {
    int i;

    /**
     * Registers a signal handler for SIGINT (to terminate the process)
     * to exit the program gracefully for Valgrind to show the program report.
     */
    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        fprintf(stderr, "Failed to set up signal handler for SIGINT\nError code: %d\n", errno);
        assert(0);
    }

    _p_global_arena_raw = arena_init(PAGE_SIZE * 50);

    /** To look up data stored in arena */
    _p_global_arena_data = (GlobalArenaDataLookup *)arena_alloc(_p_global_arena_raw, sizeof(GlobalArenaDataLookup));

    Dict envs = load_env_variables(ENV_FILE_PATH);

    const char *public_base_path = find_value("COMPILE_PUBLIC_FOLDER", envs);
    load_public_files(public_base_path);

    const char *html_base_path = find_value("COMPILE_TEMPLATES_FOLDER", envs);
    load_templates(html_base_path); /** TODO: Review the code inside this function */

    epoll_fd = epoll_create1(0);
    assert(epoll_fd != -1);

    const char *port_str = find_value("PORT", envs);

    char *endptr;
    long port = strtol(port_str, &endptr, 10);

    if (*endptr != '\0' || port < 0 || port > 65535) {
        fprintf(stderr, "Invalid port number: %s\n", port_str);
        assert(0);
    }

    Socket *server_socket = create_server_socket((uint16_t)port);
    int server_fd = server_socket->fd;

    event.events = EPOLLIN;
    event.data.ptr = server_socket;
    assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) != -1);

    printf("Server listening on port: %d...\n", (int)port);

    create_connection_pool(envs);

    /** Clear envs for security */
    memset(envs.start_addr, 0, envs.end_addr - envs.start_addr);

    struct sockaddr_in client_addr; /** Why is this needed ?? */
    socklen_t client_addr_len = sizeof(client_addr);

    while (1) {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, BLOCK_EXECUTION);

        if (keep_running == 0) {
            printf("breaking out\n");
            break;
        }

        assert(nfds != -1);

        for (i = 0; i < nfds; i++) {
            Socket *socket_info = (Socket *)events[i].data.ptr;

            switch (socket_info->type) {
                case SERVER_SOCKET: {
                    if (events[i].events & EPOLLIN) { /** Server received new client request */
                        int client_fd = accept(socket_info->fd, (struct sockaddr *)&client_addr, &client_addr_len);
                        assert(client_fd != -1);

                        int client_fd_flags = fcntl(client_fd, F_GETFL, 0);
                        assert(fcntl(client_fd, F_SETFL, client_fd_flags | O_NONBLOCK) != -1);

                        /** Allocate memory for handling client request */
                        Arena *scratch_arena_raw = arena_init(PAGE_SIZE * 10);
                        Socket *client_socket_info = (Socket *)arena_alloc(scratch_arena_raw, sizeof(Socket));
                        client_socket_info->type = CLIENT_SOCKET;
                        client_socket_info->fd = client_fd;

                        ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)arena_alloc(scratch_arena_raw, sizeof(ScratchArenaDataLookup));
                        scratch_arena_data->arena = scratch_arena_raw;
                        scratch_arena_data->client_socket = client_fd;

                        event.events = EPOLLIN | EPOLLET;
                        event.data.ptr = client_socket_info;
                        assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) != -1);

                        break;
                    }

                    printf("Server socket only should receive EPOLLIN events\n");
                    assert(0);

                    break;
                }

                case CLIENT_SOCKET: { /** Client socket (aka. client request) ready for read */
                    if (events[i].events & EPOLLIN) {
                        Arena *scratch_arena_raw = (Arena *)((uint8_t *)socket_info - sizeof(Arena));

                        if (setjmp(ctx) == 0) {
                            router(scratch_arena_raw);
                        }

                        break;
                    }

                    printf("Client socket only should receive EPOLLIN events\n");
                    assert(0);

                    break;
                }

                case DB_SOCKET: {
                    if (events[i].events & EPOLLIN) { /** DB socket (aka. connection) ready for read */
                        DBConnection *connection = (DBConnection *)socket_info;

                        /** The connection should belong to a client fd (aka. client request) */
                        assert(connection->client.fd != 0);

                        /** Postgres query response is ready for read, jump back to code and
                         * pass index to restore request state through connection pool */
                        longjmp(connection->client.jmp_buf, to_index(connection->index));
                    } else if (events[i].events & EPOLLOUT) { /** DB socket (aka connection) is ready for write */
                        DBConnection *connection = (DBConnection *)socket_info;

                        QueuedRequest *request = NULL;

                        int j;
                        for (j = 0; j < MAX_CLIENT_CONNECTIONS; j++) {
                            if (queue[j].client.fd != 0) {
                                /** First client request in the queue waiting for connection */
                                request = &(queue[j]);

                                break;
                            }
                        }

                        if (request) {
                            connection->client = request->client;
                            memcpy(&(connection->client), &(request->client), sizeof(Client));
                            memset(&(request->client), 0, sizeof(Client));

                            if (setjmp(db_ctx) == 0) {
                                /* Request handler queued the request because no connection was
                                 * available in the pool, here we jump back to code after queuing request */
                                longjmp(connection->client.jmp_buf, to_index(connection->index));
                            }
                        }
                    }

                    break;
                }

                default: {
                    assert(0);

                    break;
                }
            }
        }
    }

    close(server_fd);

    for (i = 0; i < CONNECTION_POOL_SIZE; i++) {
        PQfinish(connection_pool[i].conn);
    }

    arena_free(_p_global_arena_raw);

    return 0;
}

void router(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    int client_socket = scratch_arena_data->client_socket;

    char *request = (char *)scratch_arena_raw->current;
    scratch_arena_data->request = scratch_arena_raw->current;

    char *tmp_request = request;

    ssize_t read_stream = 0;
    ssize_t buffer_size = KB(2);

    int8_t does_http_request_contain_body = -1; /* -1 means we haven't checked yet */
    String method;

    int8_t is_multipart_form_data = -1; /* -1 means we haven't checked yet */
    String content_type;

    while (1) {
        char *advanced_request_ptr = tmp_request + read_stream;

        ssize_t incomming_stream_size = recv(client_socket, advanced_request_ptr, buffer_size - read_stream, 0);
        if (incomming_stream_size == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (read_stream > 0) {
                    break;
                }

                longjmp(ctx, 1);
            }
        }

        if (incomming_stream_size <= 0) {
            printf("fd %d - Empty request\n", scratch_arena_data->client_socket);
            return;
        }

        /**
         * NOTE: While it is possible to decode the entire HTTP request here at once,
         * we avoid doing so to prevent potential issues with requests containing
         * non-textual data, such as images or binary files. Processing such data
         * inappropriately could lead to corruption or unexpected behavior.
         */

        read_stream += incomming_stream_size;

        if (does_http_request_contain_body == -1) {
            method = find_http_request_value("METHOD", advanced_request_ptr);

            if (strncmp("GET", method.start_addr, method.length) == 0 || strncmp("HEAD", method.start_addr, method.length) == 0) {
                does_http_request_contain_body = 0;
            } else {
                does_http_request_contain_body = 1;
            }
        }

        if (!does_http_request_contain_body) {
            uint8_t request_ended = 0;

            char *current_start = advanced_request_ptr;
            char *current_end = advanced_request_ptr + incomming_stream_size;

            while (current_start < current_end) {
                char header_end[] = "\r\n\r\n";
                if (strncmp(current_start, header_end, strlen(header_end)) == 0) {
                    request_ended = 1;
                    break;
                }

                current_start++;
            }

            if (request_ended) {
                break;
            }
        }

        if (is_multipart_form_data == -1) {
            content_type = find_http_request_value("Content-Type", advanced_request_ptr);

            if (strncmp("multipart/form-data", content_type.start_addr, content_type.length) == 0) {
                is_multipart_form_data = 1;
            } else {
                is_multipart_form_data = 0;
            }
        }

        if (is_multipart_form_data) {
            uint8_t request_ended = 0;

            char *current_start = advanced_request_ptr;
            char *current_end = advanced_request_ptr + incomming_stream_size;

            while (current_start < current_end) {
                char multipart_form_data_end[] = "--\r\n";
                if (strncmp(current_start, multipart_form_data_end, strlen(multipart_form_data_end)) == 0) {
                    request_ended = 1;
                    break;
                }

                current_start++;
            }

            if (request_ended) {
                break;
            }
        }

        if (read_stream >= buffer_size) {
            buffer_size += KB(2);
        }
    }

    tmp_request += read_stream;
    (*tmp_request) = '\0';
    tmp_request++;

    scratch_arena_raw->current = tmp_request;

    String url = find_http_request_value("URL", scratch_arena_data->request);

    if (strncmp(url.start_addr, URL("/manifest.json"), strlen(URL("/manifest.json"))) == 0 && strncmp(method.start_addr, "GET", method.length) == 0) {
        char buff[] = "/public/manifest.json";
        String new_url = {0};
        new_url.start_addr = buff;
        new_url.length = strlen(buff);

        public_get(scratch_arena_raw, new_url);
        return;
    }
    if (strncmp(url.start_addr, URL("/.well-known/assetlinks.json"), strlen(URL("/.well-known/assetlinks.json"))) == 0 && strncmp(method.start_addr, "GET", method.length) == 0) {
        char buff[] = "/public/.well-known/assetlinks.json";
        String new_url = {0};
        new_url.start_addr = buff;
        new_url.length = strlen(buff);

        public_get(scratch_arena_raw, new_url);
        return;
    }

    if (strncmp(url.start_addr, "/public", strlen("/public")) == 0 && strncmp(method.start_addr, "GET", method.length) == 0) {
        public_get(scratch_arena_raw, url);
        return;
    }

    if (strncmp(url.start_addr, URL("/"), strlen(URL("/"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            home_get(scratch_arena_raw);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/test"), strlen(URL("/test"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            test_get(scratch_arena_raw);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/login"), strlen(URL("/login"))) == 0 || strncmp(url.start_addr, URL_WITH_QUERY("/login"), strlen(URL_WITH_QUERY("/login"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            view_get(scratch_arena_raw, "login", true);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/login/create-session"), strlen(URL("/login/create-session"))) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            login_create_session_post(scratch_arena_raw);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/register"), strlen(URL("/register"))) == 0 || strncmp(url.start_addr, URL_WITH_QUERY("/register"), strlen(URL_WITH_QUERY("/register"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            view_get(scratch_arena_raw, "register", true);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/register/create-account"), strlen(URL("/register/create-account"))) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            register_create_account_post(scratch_arena_raw);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/auth"), strlen(URL("/auth"))) == 0 || strncmp(url.start_addr, URL_WITH_QUERY("/auth"), strlen(URL_WITH_QUERY("/auth"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            view_get(scratch_arena_raw, "auth", true);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/auth/validate-email"), strlen(URL("/auth/validate-email"))) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            auth_validate_email_post(scratch_arena_raw);
            return;
        }
    }

    view_get(scratch_arena_raw, "not_found", false);

    return;
}

/**
 * Parses and decodes URL query or request body parameters into a dictionary.
 */
Dict parse_and_decode_params(Arena *scratch_arena_raw, String raw_params) {
    Dict key_value = {0};

    if (raw_params.length == 0) {
        return key_value;
    }

    char *ptr = raw_params.start_addr;
    char *raw_params_end = raw_params.start_addr + raw_params.length;

    char *params_dict = (char *)scratch_arena_raw->current;
    key_value.start_addr = params_dict;

    if (*ptr == '?') {
        /** skip '?' at the beginning of query params string */
        ptr++;
    }

    while (ptr < raw_params_end) {
        char *key = ptr;
        char *key_end = key;
        while (*key_end != '=') {
            key_end++;
        }

        size_t key_length = key_end - key;
        memcpy(params_dict, key, key_length);
        params_dict += key_length;
        *params_dict = '\0';
        params_dict++;

        /** TODO: Check if it is possible that query param does not have a value? 🤔 */

        char *val = key_end + 1; /** +1 to skip '=' */
        char *val_end = val;
        while (*val_end != '&' && !isspace(*val_end) && *val_end != '\0') {
            val_end++;
        }

        size_t val_length = val_end - val;
        memcpy(params_dict, val, val_length);
        size_t new_val_length = url_decode_utf8(&params_dict, val_length);
        params_dict += new_val_length;
        *params_dict = '\0';
        params_dict++;

        ptr = val_end + 1; /** +1 to skip possible '&' which marks the end of query (or body) param key-value and beginning of new one */
    }

    key_value.end_addr = params_dict - 1; /** -1 because we (params_dict++) at the end of query (or body) param value processing */

    scratch_arena_raw->current = params_dict;

    return key_value;
}

void resolve_slots(char *component_markdown, char *import_statement, char **templates) {
    char *ptr;

    char *tmp_templates = *templates;
    while (*tmp_templates) {
        if (strncmp(tmp_templates, COMPONENT_IMPORT_CLOSING_TAG, strlen(COMPONENT_IMPORT_CLOSING_TAG)) == 0) {
            char *component_import_closing_tag = strstr(import_statement, COMPONENT_IMPORT_CLOSING_TAG);
            char *passed_component_import_closing_tag = component_import_closing_tag + strlen(COMPONENT_IMPORT_CLOSING_TAG);

            size_t component_markdown_length = strlen(component_markdown);
            memmove((*templates) + component_markdown_length, passed_component_import_closing_tag, strlen(passed_component_import_closing_tag));
            ptr = (*templates) + component_markdown_length + strlen(passed_component_import_closing_tag);
            ptr[0] = '\0';
            ptr++;
            while (*ptr) {
                size_t str_len = strlen(ptr);
                memset(ptr, 0, str_len);
                ptr += str_len + 1;
            }

            memcpy((*templates), component_markdown, component_markdown_length);

            char *start = *templates;
            char *end = (*templates) + component_markdown_length;
            while ((start + strlen(SLOT_TAG)) < end) {
                if (strncmp(start, SLOT_TAG, strlen(SLOT_TAG)) == 0) {
                    char *passed_slot_tag = start + strlen(SLOT_TAG);
                    memmove(start, passed_slot_tag, strlen(passed_slot_tag));
                    ptr = start + strlen(passed_slot_tag);
                    ptr[0] = '\0';
                    ptr++;
                    while (*ptr) {
                        size_t str_len = strlen(ptr);
                        memset(ptr, 0, str_len);
                        ptr += str_len + 1;
                    }
                }

                start++;
            }

            return;
        }

        if (strncmp(tmp_templates, TEMPLATE_OPENING_TAG, strlen(TEMPLATE_OPENING_TAG)) == 0) {
            break;
        }

        tmp_templates++;
    }

    char *slot_tag_inside_component_markdown = strstr(component_markdown, SLOT_TAG);

    char *template_opening_tag = strstr(import_statement, TEMPLATE_OPENING_TAG);
    char *passed_template_opening_tag = template_opening_tag + strlen(TEMPLATE_OPENING_TAG);

    size_t portion = slot_tag_inside_component_markdown - component_markdown;

    memmove((*templates) + portion, passed_template_opening_tag, strlen(passed_template_opening_tag));
    ptr = (*templates) + portion + strlen(passed_template_opening_tag);
    ptr[0] = '\0';
    ptr++;
    while (*ptr) {
        size_t str_len = strlen(ptr);
        memset(ptr, 0, str_len);
        ptr += str_len + 1;
    }

    memcpy((*templates), component_markdown, portion);

    (*templates) += portion;
    component_markdown += portion;
    component_markdown += strlen(SLOT_TAG);

    char *template_closing_tag = (*templates);
    uint8_t skip = 0;
    while (*template_closing_tag) {
        if (strncmp(template_closing_tag, TEMPLATE_OPENING_TAG, strlen(TEMPLATE_OPENING_TAG)) == 0) {
            skip++;
        }

        if (strncmp(template_closing_tag, TEMPLATE_CLOSING_TAG, strlen(TEMPLATE_CLOSING_TAG)) == 0) {
            if (skip == 0) {
                break;
            }

            skip--;
        }

        template_closing_tag++;
    }

    char *passed_template_closing_tag = template_closing_tag + strlen(TEMPLATE_CLOSING_TAG);
    memmove(template_closing_tag, passed_template_closing_tag, strlen(passed_template_closing_tag));
    ptr = template_closing_tag + strlen(passed_template_closing_tag);
    ptr[0] = '\0';
    ptr++;
    while (*ptr) {
        size_t str_len = strlen(ptr);
        memset(ptr, 0, str_len);
        ptr += str_len + 1;
    }

    (*templates) = template_closing_tag;
    resolve_slots(component_markdown, template_closing_tag, templates);
}

/**
 * Scans the `request` for the `\r\n\r\n` sequence that separates headers from the body
 * and returns a pointer to the body start. Return Pointer to the start of the body or
 * NULL if no body is found.
 */
String find_body(const char *request) {
    String body = {0};
    char *ptr = (char *)request;

    char request_headers_end[] = "\r\n\r\n";

    char *request_end = (char *)request + strlen(request);
    while (ptr < request_end) {
        if (strncmp(ptr, request_headers_end, strlen(request_headers_end)) == 0) {
            ptr += strlen(request_headers_end);

            body.start_addr = ptr;
            body.length = strlen(ptr);

            return body;
        }

        ptr++;
    }

    return body;
}

/**
 * Searches the `body` for the specified `key` and returns its
 * corresponding value as a `String`.
 */
String find_body_value(const char key[], String body) {
    /** TODO: Check whether key can have no value */
    String value = {0};

    char *ptr = body.start_addr;
    char *body_end = body.start_addr + body.length + 1;

    while (ptr < body_end) {
        if (strncmp(ptr, key, strlen(key)) == 0) {
            char *key_end = ptr + strlen(key);

            if (*key_end == '=') {
                key_end++;
                value.start_addr = key_end;
                break;
            }
        }

        ptr++;
    }

    char *value_end = value.start_addr;
    while (value_end < body_end) {
        if (*value_end == '&' || *value_end == '\0') {
            value.length = value_end - value.start_addr;

            break;
        }

        value_end++;
    }

    return value;
}

/**
 * Generic handler for pages (e.g., login, registration) that do not require
 * authentication. when `accepts_query_params` is true, query values are
 * rendered in their respective template placeholders.
 */
void view_get(Arena *scratch_arena_raw, char *view, boolean accepts_query_params) {
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    Dict replaces = {0};
    if (accepts_query_params) {
        String query_params = find_http_request_value("QUERY_PARAMS", scratch_arena_data->request);

        if (query_params.length > 0) {
            replaces = parse_and_decode_params(scratch_arena_raw, query_params);
        }
    }

    int client_socket = scratch_arena_data->client_socket;

    char *template = find_value(view, p_global_arena_data->templates);

    if (replaces.start_addr) {
        char *template_cpy = (char *)scratch_arena_raw->current;
        memcpy(template_cpy, template, strlen(template) + 1);

        char *ptr = replaces.start_addr;
        while (ptr < replaces.end_addr) {
            char *key = ptr;
            char *value = ptr + strlen(ptr) + 1;

            replace_val(template_cpy, key, value);

            ptr += strlen(ptr) + 1; /* pass key */
            ptr += strlen(ptr) + 1; /* pass value */
        }

        scratch_arena_raw->current = (char *)scratch_arena_raw->current + strlen(template_cpy) + 1;

        /** Re-set template to point to "rendered template copy" */
        template = template_cpy;
    }

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    size_t response_length = strlen(response_headers) + strlen(template);

    char *response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, template);
    response[response_length] = '\0';

    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);

    arena_free(scratch_arena_raw);
}

/**
 * Searches the connection pool for an available connection (where `client.fd` is 0) and assigns
 * the current request (represented by `scratch_arena_raw`) to it; returns `NULL` if the pool is full.
 *
 * Searches the request queue for an available slot (where `client.fd` is 0) and associates the
 * current request (represented by `scratch_arena_raw`) with it, marking the request as queued;
 * returns a pointer to the assigned queue slot.
 */
DBConnection *get_available_connection(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    int i;

    for (i = 0; i < CONNECTION_POOL_SIZE; i++) {
        if (connection_pool[i].client.fd == 0) {

            connection_pool[i].client.fd = scratch_arena_data->client_socket;
            connection_pool[i].client.scratch_arena_data = scratch_arena_data;

            DBConnection *connection = &(connection_pool[i]);

            return connection;
        }
    }

    for (i = 0; i < MAX_CLIENT_CONNECTIONS; i++) {
        if (queue[i].client.fd == 0) {
            /* Available spot in the queue */

            queue[i].client.fd = scratch_arena_data->client_socket;
            queue[i].client.scratch_arena_data = scratch_arena_data;
            queue[i].client.queued = 1;

            QueuedRequest *queued = &(queue[i]);

            int r = setjmp(queued->client.jmp_buf);
            if (r == 0) {
                longjmp(ctx, 1);
            }

            int index = from_index(r);

            DBConnection *connection = &(connection_pool[index]);

            return connection;
        }
    }

    assert(0);
}

Stack WPQsendQueryParamsStackBuffer;
DBQueryCtx WPQsendQueryParams(DBConnection *connection, const char *command, int nParams, const Oid *paramTypes, const char *const *paramValues, const int *paramLengths, const int *paramFormats, int resultFormat) {
    /*
    DECLARE_STACK_MARKER;
    */

    if (PQsendQueryParams(connection->conn, command, nParams, paramTypes, paramValues, paramLengths, paramFormats, resultFormat) == 0) {
        fprintf(stderr, "Query failed to send: %s\n", PQerrorMessage(connection->conn));
        int conn_fd = PQsocket(connection->conn);
        printf("socket: %d", conn_fd);
    }

    int conn_fd = PQsocket(connection->conn);

    event.events = EPOLLIN | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_fd, &event);

    int index;
    /*
    SAVE_STACK_STATE(WPQsendQueryParamsStackBuffer);
    */
    if (connection->client.queued) {
        int r = setjmp(connection->client.jmp_buf);
        if (r == 0) {
            longjmp(db_ctx, 1);
        }

        index = from_index(r);
    } else {
        int r = setjmp(connection->client.jmp_buf);
        if (r == 0) {
            longjmp(ctx, 1);
        }

        index = from_index(r);
    }

    /*
    restore_stack_state(WPQsendQueryParamsStackBuffer);
    */

    printf("%d\n", index);

    PGresult *result = get_result(connection);

    DBQueryCtx output = {0};
    output.result = result;
    output.connection = connection;

    return output;
}

String find_cookie_value(const char *key, String cookies) {
    String value = {0};

    if (!cookies.start_addr && cookies.length == 0) {
        return value;
    }

    char *ptr = cookies.start_addr;
    char *cookies_end = cookies.start_addr + cookies.length;

    char *end_sign = "\r\n";

    while (ptr < cookies_end) {
        if (strncmp(key, ptr, strlen(key)) == 0) {
            ptr += strlen(key);

            while (isspace(*ptr)) {
                if (ptr == cookies_end) {
                    assert(0);
                }

                ptr++;
            }

            assert(*ptr == '=');
            ptr++; /** skip '=' */

            while (isspace(*ptr)) {
                if (ptr == cookies_end) {
                    assert(0);
                }

                ptr++;
            }

            value.start_addr = ptr;

            while (*ptr != '\0' && !isspace(*ptr) && strncmp(ptr, end_sign, strlen(end_sign)) != 0) {
                ptr++;
            }

            value.length = ptr - value.start_addr;

            return value;
        }

        ptr++;
    }

    return value;
}

Stack is_authenticated_stack_buffer;
User is_authenticated(Arena *scratch_arena_raw, DBConnection *connection) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    User user = {0};

    String cookie = find_http_request_value("Cookie", scratch_arena_data->request);
    if (cookie.start_addr && cookie.length) {
        String session_id_reference = find_cookie_value("session_id", cookie);
        if (session_id_reference.start_addr && session_id_reference.length) {
            uuid_str_t session_id_str;
            memset(session_id_str, 0, sizeof(uuid_str_t));
            memcpy(session_id_str, session_id_reference.start_addr, session_id_reference.length);
            session_id_str[session_id_reference.length] = '\0';

            uuid_t session_id;
            memset(session_id, 0, sizeof(uuid_t));
            uuid_parse(session_id_str, session_id);

            const char *command_1 = "SELECT u.id, u.email "
                                    "FROM app.users_sessions us "
                                    "JOIN app.users u ON u.id = us.user_id "
                                    "WHERE us.id = $1 AND NOW() < us.expires_at";

            Oid paramTypes_1[N1_PARAMS] = {2950};
            const char *paramValues_1[N1_PARAMS];
            paramValues_1[0] = (const char *)session_id;
            int paramLengths_1[N1_PARAMS] = {16};
            int paramFormats_1[N1_PARAMS] = {1};

            DBQueryCtx query_ctx_1 = WPQsendQueryParams(connection, command_1, N1_PARAMS, paramTypes_1, paramValues_1, paramLengths_1, paramFormats_1, TEXT);
            PGresult *result_1 = query_ctx_1.result;

            int num_rows = PQntuples(result_1);
            if (num_rows) {
                print_query_result(result_1);

                char *user_info = (char *)scratch_arena_raw->current;
                char *tmp_user_info = user_info;

                char *user_id = PQgetvalue(result_1, 0, 0);
                memcpy(tmp_user_info, "user_id", strlen("user_id"));
                tmp_user_info += strlen("user_id");
                *tmp_user_info = '\0';
                tmp_user_info++;

                memcpy(tmp_user_info, user_id, strlen(user_id));
                tmp_user_info += strlen(user_id);
                *tmp_user_info = '\0';
                tmp_user_info++;

                char *user_email = PQgetvalue(result_1, 0, 1);
                memcpy(tmp_user_info, "user_email", strlen("user_email"));
                tmp_user_info += strlen("user_email");
                *tmp_user_info = '\0';
                tmp_user_info++;

                memcpy(tmp_user_info, user_email, strlen(user_email));
                tmp_user_info += strlen(user_email);
                *tmp_user_info = '\0';

                user.start_addr = user_info;
                user.end_addr = tmp_user_info;

                scratch_arena_raw->current = tmp_user_info + 1;

                PQclear(result_1);

                return user;
            }
        }
    }

    return user;
}

Stack home_get_stack_buffer;
void home_get(Arena *scratch_arena_raw) {
    /*
    DECLARE_STACK_MARKER;
    */

    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));
    DBConnection *connection = get_available_connection(scratch_arena_raw);

    char *template = find_value("home", _p_global_arena_data->templates);

    char *response = NULL;

    User user = is_authenticated(scratch_arena_raw, connection);
    if (user.start_addr) {
        char *template_cpy = (char *)scratch_arena_raw->current;

        memcpy(template_cpy, template, strlen(template) + 1);

        render_val(template_cpy, "authenticated", "Account");
        replace_val(template_cpy, "authenticated_redirect", "/account");

        scratch_arena_raw->current = (char *)scratch_arena_raw->current + strlen(template_cpy) + 1;

        char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        size_t response_length = strlen(response_headers) + strlen(template_cpy);

        response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

        sprintf(response, "%s%s", response_headers, template_cpy);
        response[response_length] = '\0';

        goto send_response;
    }

    char *template_cpy = (char *)scratch_arena_raw->current;

    memcpy(template_cpy, template, strlen(template) + 1);

    render_val(template_cpy, "authenticated", "Login");
    replace_val(template_cpy, "authenticated_redirect", "/auth");

    scratch_arena_raw->current = (char *)scratch_arena_raw->current + strlen(template_cpy) + 1;

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    size_t response_length = strlen(response_headers) + strlen(template_cpy);

    response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, template_cpy);
    response[response_length] = '\0';

send_response:
    if (send(scratch_arena_data->client_socket, response, strlen(response), 0) == -1) {
    }

    close(scratch_arena_data->client_socket);

    release_request_resources_and_exit(scratch_arena_raw, connection);
}

void login_create_session_post(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    DBConnection *connection = get_available_connection(scratch_arena_raw);

    String body = find_body(scratch_arena_data->request);
    Dict params = parse_and_decode_params(scratch_arena_raw, body);

    char *email = find_value("email", params);

    const char *command_1 = "SELECT id, password FROM app.users WHERE email = $1";

    Oid paramTypes_1[N1_PARAMS] = {25};
    const char *paramValues_1[N1_PARAMS];
    paramValues_1[0] = email;
    int paramLengths_1[N1_PARAMS] = {0};
    int paramFormats_1[N1_PARAMS] = {0};

    DBQueryCtx query_ctx_1 = WPQsendQueryParams(connection, command_1, N1_PARAMS, paramTypes_1, paramValues_1, paramLengths_1, paramFormats_1, BINARY);

    PGresult *result_1 = query_ctx_1.result;
    print_query_result(result_1);

    char *password = find_value("password", params);
    char *stored_password = PQgetvalue(result_1, 0, 1); /* First row, Second column */

    if (argon2i_verify(stored_password, password, strlen(password)) != ARGON2_OK) {
        fprintf(stderr, "Failed to verify password\nError code: %d\n", errno);
    }

    unsigned char *user_id = (unsigned char *)PQgetvalue(result_1, 0, 0);

    /** Create session */
    const char *command_2 = "INSERT INTO app.users_sessions (user_id, expires_at) "
                            "VALUES ($1, NOW() + INTERVAL '1 hour') "
                            "ON CONFLICT (user_id) DO UPDATE SET "
                            "updated_at = NOW(), expires_at = EXCLUDED.expires_at "
                            "RETURNING id, to_char(expires_at, 'Dy, DD Mon YYYY HH24:MI:SS GMT') AS expires_at;";

    Oid paramTypes_2[N1_PARAMS] = {2950};
    const char *paramValues_2[N1_PARAMS];
    paramValues_2[0] = (const char *)user_id;
    int paramLengths_2[N1_PARAMS] = {16};
    int paramFormats_2[N1_PARAMS] = {1};

    DBQueryCtx query_ctx_2 = WPQsendQueryParams(connection, command_2, N1_PARAMS, paramTypes_2, paramValues_2, paramLengths_2, paramFormats_2, TEXT);

    PQclear(result_1);

    PGresult *result_2 = query_ctx_2.result;
    print_query_result(result_2);

    char *response = (char *)scratch_arena_raw->current;

    char *session_id = PQgetvalue(result_2, 0, 0);
    char *expires_at = PQgetvalue(result_2, 0, 1);

    sprintf(response,
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session_id=%s; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=%s\r\n"
            "HX-Redirect: /\r\n\r\n",
            session_id, expires_at);

    PQclear(result_2);

    scratch_arena_raw->current = response + strlen(response) + 1;

    if (send(scratch_arena_data->client_socket, response, strlen(response), 0) == -1) {
    }

    close(scratch_arena_data->client_socket);

    release_request_resources_and_exit(scratch_arena_raw, connection);
}

int generate_salt(uint8_t *salt, size_t salt_size) {
    FILE *dev_urandom = fopen("/dev/urandom", "rb");
    if (dev_urandom == NULL) {
        fprintf(stderr, "Error opening /dev/urandom\nError code: %d\n", errno);
        return -1;
    }

    if (fread(salt, 1, salt_size, dev_urandom) != salt_size) {
        fprintf(stderr, "Error reading from /dev/urandom\nError code: %d\n", errno);
        fclose(dev_urandom);
        return -1;
    }

    fclose(dev_urandom);

    return 0;
}

int copy_string_into_buffer(char *buffer, const char *string) {
    size_t string_length = strlen(string);

    if (memcpy(buffer, string, string_length) == NULL) {
        fprintf(stderr, "Failed to copy string into buffer\nError code: %d\n", errno);
        return -1;
    }

    buffer[string_length] = '\0';

    return 0;
}

int validate_repeat_password(char *error_message_buffer, const char *password, const char *repeat_password) {
    if (strlen(password) == 0) {
        if (copy_string_into_buffer(error_message_buffer, "Should provide a repeat password") == -1) {
            return -1;
        }

        return 0;
    }

    if (strcmp(password, repeat_password) != 0) {
        if (copy_string_into_buffer(error_message_buffer, "Password and repeat password should match") == -1) {
            return -1;
        }

        return 0;
    }

    if (copy_string_into_buffer(error_message_buffer, "") == -1) {
        return -1;
    }

    return 0;
}

int validate_password(char *error_message_buffer, const char *password) {
    if (strlen(password) == 0) {
        if (copy_string_into_buffer(error_message_buffer, "Should provide a password") == -1) {
            return -1;
        }

        return 0;
    }

    if (strlen(password) < 4) {
        if (copy_string_into_buffer(error_message_buffer, "Password should be at least 4 characters") == -1) {
            return -1;
        }

        return 0;
    }

    if (copy_string_into_buffer(error_message_buffer, "") == -1) {
        return -1;
    }

    return 0;
}

int validate_email(char *error_message_buffer, const char *email) {
    regex_t regex;

    if (regcomp(&regex, EMAIL_REGEX, REG_EXTENDED) != 0) {
        fprintf(stderr, "Could not compile regex\nError code: %d\n", errno);
        return -1;
    }

    if (regexec(&regex, email, 0, NULL, 0) == REG_NOMATCH) {
        if (copy_string_into_buffer(error_message_buffer, "Email should be of format example@example.com") == -1) {
            return -1;
        }

        return 0;
    }

    if (copy_string_into_buffer(error_message_buffer, "") == -1) {
        return -1;
    }

    return 0;
}

void register_create_account_post(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    DBConnection *connection = get_available_connection(scratch_arena_raw);

    String body = find_body(scratch_arena_data->request);
    Dict params = parse_and_decode_params(scratch_arena_raw, body);

    char *email = find_value("email", params);
    char *password = find_value("password", params);
    char *repeat_password = find_value("password-again", params);

    char validation_error_msg[255];

    if (validate_email(validation_error_msg, email) == -1) {
    }

    if (validate_password(validation_error_msg, password) == -1) {
    }

    if (validate_repeat_password(validation_error_msg, password, repeat_password) == -1) {
    }

    /** Hash user password */
    uint8_t salt[SALT_LENGTH];
    memset(salt, 0, SALT_LENGTH);

    if (generate_salt(salt, SALT_LENGTH) == -1) {
    }

    uint32_t t_cost = 2;         /* 2-pass computation */
    uint32_t m_cost = (1 << 16); /* 64 mebibytes memory usage */
    uint32_t parallelism = 1;    /* number of threads and lanes */

    uint8_t hash[HASH_LENGTH];
    memset(hash, 0, HASH_LENGTH);

    char secure_password[PASSWORD_BUFFER];
    memset(secure_password, 0, PASSWORD_BUFFER);
    if (argon2i_hash_raw(t_cost, m_cost, parallelism, password, strlen(password), salt, SALT_LENGTH, hash, HASH_LENGTH) != ARGON2_OK) {
        fprintf(stderr, "Failed to create hash from password\nError code: %d\n", errno);
    }

    if (argon2i_hash_encoded(t_cost, m_cost, parallelism, password, strlen(password), salt, SALT_LENGTH, HASH_LENGTH, secure_password, PASSWORD_BUFFER) != ARGON2_OK) {
        fprintf(stderr, "Failed to encode hash\nError code: %d\n", errno);
    }

    if (argon2i_verify(secure_password, password, strlen(password)) != ARGON2_OK) {
        fprintf(stderr, "Failed to verify password\nError code: %d\n", errno);
    }

    printf("%s\n", secure_password);

    const char *command = "INSERT INTO app.users (email, password) VALUES ($1, $2)";
    Oid paramTypes[2] = {25, 25};
    const char *paramValues[2];
    paramValues[0] = email;
    paramValues[1] = secure_password;
    int paramLengths[2] = {0, 0};
    int paramFormats[2] = {0, 0};
    int resultFormat = 0;

    if (PQsendQueryParams(connection->conn, command, 2, paramTypes, paramValues, paramLengths, paramFormats, resultFormat) == 0) {
        fprintf(stderr, "Query failed to send: %s\n", PQerrorMessage(connection->conn));
        int _conn_fd = PQsocket(connection->conn);
        printf("socket: %d", _conn_fd);
    }

    int _conn_fd = PQsocket(connection->conn);

    event.events = EPOLLIN | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, _conn_fd, &event);

    int index;

    if (connection->client.queued) {
        int r = setjmp(connection->client.jmp_buf);
        if (r == 0) {
            longjmp(db_ctx, 1);
        }

        index = from_index(r);
    } else {
        int r = setjmp(connection->client.jmp_buf);
        if (r == 0) {
            longjmp(ctx, 1);
        }

        index = from_index(r);
    }

    printf("%d", index);

    PGresult *result = get_result(connection);
    print_query_result(result);
    PQclear(result);

    char response_headers[] = "HTTP/1.1 200 OK\r\nHX-Redirect: /\r\n\r\n";

    int client_socket = scratch_arena_data->client_socket;
    if (send(client_socket, response_headers, strlen((char *)response_headers), 0) == -1) {
    }

    close(client_socket);

    release_request_resources_and_exit(scratch_arena_raw, connection);
}

/**
 * Encapsulates boilerplate logic for processing query results in an asynchronous
 * PostgreSQL connection. Ensures all input is consumed, waits for the query to finish,
 * and retrieves the first valid result from the connection. The returned `PGresult`
 * must be cleared with `PQclear` after use to avoid memory leaks.
 */
PGresult *get_result(DBConnection *connection) {
    if (!PQconsumeInput(connection->conn)) {
        assert(0);
    }

    while (PQisBusy(connection->conn)) {
        if (!PQconsumeInput(connection->conn)) {
            assert(0);
        }
    }

    PGresult *result = NULL;

    PGresult *ptr = NULL;
    int did_set_ptr = 0;
    while ((ptr = PQgetResult(connection->conn)) != NULL) {
        if (did_set_ptr == 0) {
            result = ptr;
            did_set_ptr = 1;
        }

        if (PQresultStatus(ptr) != PGRES_TUPLES_OK && PQresultStatus(ptr) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Query failed: %s\n", PQerrorMessage(connection->conn));

            assert(0);
        }
    }

    return result;
}

void auth_validate_email_post(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    DBConnection *connection = get_available_connection(scratch_arena_raw);

    String body = find_body(scratch_arena_data->request);
    Dict params = parse_and_decode_params(scratch_arena_raw, body);

    char *email = find_value("email", params);

    const char *command = "SELECT email FROM app.users WHERE email = $1";
    Oid paramTypes[1] = {25};
    const char *paramValues[1];
    paramValues[0] = email;
    int paramLengths[1] = {0};
    int paramFormats[1] = {0};
    int resultFormat = 0;

    if (PQsendQueryParams(connection->conn, command, 1, paramTypes, paramValues, paramLengths, paramFormats, resultFormat) == 0) {
        fprintf(stderr, "Query failed to send: %s\n", PQerrorMessage(connection->conn));
    }

    int conn_socket = PQsocket(connection->conn);

    event.events = EPOLLIN | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_socket, &event);

    int index;
    if (connection->client.queued) {
        int r = setjmp(connection->client.jmp_buf);
        if (r == 0) {
            longjmp(db_ctx, 1);
        }

        index = from_index(r);
    } else {
        int r = setjmp(connection->client.jmp_buf);
        if (r == 0) {
            longjmp(ctx, 1);
        }

        index = from_index(r);
    }

    printf("%d", index);

    PGresult *result = get_result(connection);

    int rows = PQntuples(result);
    print_query_result(result);
    PQclear(result);

    char *response_headers[200];
    memset(response_headers, 0, sizeof(response_headers));

    String encoded_email = find_body_value("email", body);

    if (rows > 0) {
        sprintf((char *)response_headers, "HTTP/1.1 200 OK\r\nHX-Redirect: /login?email=%.*s\r\n\r\n", (int)encoded_email.length, encoded_email.start_addr);
    } else {
        sprintf((char *)response_headers, "HTTP/1.1 200 OK\r\nHX-Redirect: /register?email=%.*s\r\n\r\n", (int)encoded_email.length, encoded_email.start_addr);
    }

    int client_socket = scratch_arena_data->client_socket;
    if (send(client_socket, response_headers, strlen((char *)response_headers), 0) == -1) {
    }

    close(client_socket);

    uint8_t was_queued = connection->client.queued;

    /* release connection for others to use */
    memset(&(connection->client), 0, sizeof(Client));

    conn_socket = PQsocket(connection->conn);

    event.events = EPOLLOUT | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_socket, &event);

    arena_free(scratch_arena_raw);

    if (was_queued) {
        longjmp(db_ctx, 1); /** Jump back */
    } else {
        longjmp(ctx, 1); /** Jump back */
    }
}

/**
 * Checks the file path's extension and returns the corresponding content type.
 * For a list of supported extensions, refer to the function implementation.
 */
char *file_content_type(Arena *scratch_arena_raw, const char *path) {
    const char *path_end = path + strlen(path);

    while (path < path_end) {
        if (strncmp(path_end, ".css", strlen(".css")) == 0) {
            char type[] = "text/css";
            char *content_type = (char *)arena_alloc(scratch_arena_raw, sizeof(type));
            memcpy(content_type, &type, sizeof(type));
            return content_type;
        }

        if (strncmp(path_end, ".js", strlen(".js")) == 0) {
            char type[] = "text/javascript";
            char *content_type = (char *)arena_alloc(scratch_arena_raw, sizeof(type));
            memcpy(content_type, &type, sizeof(type));
            return content_type;
        }

        if (strncmp(path_end, ".json", strlen(".json")) == 0) {
            char type[] = "application/json";
            char *content_type = (char *)arena_alloc(scratch_arena_raw, sizeof(type));
            memcpy(content_type, &type, sizeof(type));
            return content_type;
        }

        path_end--;
    }

    assert(0);
}

void public_get(Arena *scratch_arena_raw, String url) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char *path = (char *)arena_alloc(scratch_arena_raw, sizeof('.') + url.length);
    char *tmp_path = path;
    *tmp_path = '.';
    tmp_path++;
    strncpy(tmp_path, url.start_addr, url.length);

    char *public_file_type = file_content_type(scratch_arena_raw, path);
    char *content = find_value(path, p_global_arena_data->public_files_dict);

    char *response = (char *)scratch_arena_raw->current;

    sprintf(response,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n\r\n"
            "%s",
            public_file_type, content);

    char *response_end = response;
    while (*response_end != '\0') {
        response_end++;
    }

    scratch_arena_raw->current = response_end + 1;

    int client_socket = scratch_arena_data->client_socket;
    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);

    arena_free(scratch_arena_raw);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
BlockLocation find_block(char *template, char *block_name) {
    BlockLocation block = {0};

    char *ptr = NULL;

    while ((ptr = strstr(template, FOR_OPENING_TAG__START)) != NULL) {
        char *before = ptr;

        ptr += strlen(FOR_OPENING_TAG__START);

        if (strncmp(ptr, block_name, strlen(block_name)) == 0) {
            char *after = ptr + strlen(block_name) + strlen(FOR_OPENING_TAG__END);

            block.opening_tag.start_addr = before;
            block.opening_tag.end_addr = after;

            uint8_t inside = 0;
            while (*ptr != '\0') {
                if (strncmp(ptr, FOR_OPENING_TAG__START, strlen(FOR_OPENING_TAG__START)) == 0) {
                    inside++;
                }

                if (strncmp(ptr, FOR_CLOSING_TAG, strlen(FOR_CLOSING_TAG)) == 0) {
                    if (inside > 0) {
                        inside--;
                    } else {
                        block.closing_tag.start_addr = ptr;
                        block.closing_tag.end_addr = ptr + strlen(FOR_CLOSING_TAG);

                        return block;
                    }
                }

                ptr++;
            }
        }
    }

    return block;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
size_t replace_val(char *template, char *val_name, char *value) {
    char *ptr = template;

    char key[100];

    size_t key_length = strlen(val_name) + strlen("%%");
    assert(key_length < 100);

    sprintf(key, "%c%s%c", '%', val_name, '%');
    key[key_length] = '\0';

    while (*ptr != '\0') {
        if (strncmp(ptr, key, key_length) == 0) {
            size_t val_length = strlen(value);

            char *after = ptr + strlen(key);

            memmove(ptr + val_length, after, strlen(after) + 1);
            memcpy(ptr, value, val_length);

            ptr += strlen(ptr) + 1;

            /** Clean up memory */
            while (*ptr != '\0') {
                *ptr = '\0';
                ptr++;
            }

            return strlen(template);
        }

        ptr++;
    }

    return strlen(template);
}

size_t render_val(char *template, char *val_name, char *value) {
    char *ptr = template;
    uint8_t inside = 0;
    while (*ptr != '\0') {
        if (strncmp(ptr, FOR_OPENING_TAG__START, strlen(FOR_OPENING_TAG__START)) == 0) {
            inside++;
        }

        if (strncmp(ptr, FOR_CLOSING_TAG, strlen(FOR_CLOSING_TAG)) == 0) {
            if (inside > 0) {
                inside--;
            } else {
                assert(0);
            }
        }

        if (strncmp(ptr, VAL_OPENING_TAG__START, strlen(VAL_OPENING_TAG__START)) == 0) {
            if (inside == 0) {
                size_t value_name_length = 0;
                char *value_name = ptr + strlen(VAL_OPENING_TAG__START);
                char *tmp = value_name;

                while (*tmp != '"') {
                    value_name_length++;
                    tmp++;
                }

                TagLocation val_tag = {0};
                val_tag.start_addr = ptr;
                val_tag.end_addr = ptr + strlen(VAL_OPENING_TAG__START) + value_name_length + strlen(VAL_SELF_CLOSING_TAG__END);

                char buff[255];
                memset(buff, 0, 255);
                sprintf(buff, "%s\"", val_name);

                if (strncmp(buff, value_name, strlen(buff)) == 0) {
                    size_t val_length = strlen(value);

                    memmove(ptr + val_length, val_tag.end_addr, strlen(val_tag.end_addr) + 1);
                    memcpy(ptr, value, val_length);

                    ptr += strlen(ptr) + 1;

                    /** Clean up memory */
                    while (*ptr != '\0') {
                        *ptr = '\0';
                        ptr++;
                    }

                    return strlen(template);
                }
            }
        }

        ptr++;
    }

    assert(0);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
size_t render_for(char *template, char *block_name, int times, ...) {
    va_list args;
    CharsBlock key_value = {0};

    BlockLocation block = find_block(template, block_name);

    if (!block.opening_tag.start_addr || !block.opening_tag.end_addr || !block.closing_tag.start_addr || !block.closing_tag.end_addr) {
        /** Didn't find block */
        return strlen(template);
    }

    size_t block_length = block.closing_tag.start_addr - block.opening_tag.end_addr;

    char *block_copy = (char *)malloc((block_length + 1) * sizeof(char));
    memcpy(block_copy, block.opening_tag.end_addr, block_length);
    block_copy[block_length] = '\0';
    char *block_copy_end = block_copy + block_length;

    char *start = block.opening_tag.start_addr;

    size_t after_copy_lenght = strlen(block.closing_tag.end_addr);
    char *after_copy = (char *)malloc((after_copy_lenght + 1) * sizeof(char));
    memcpy(after_copy, block.closing_tag.end_addr, after_copy_lenght);
    after_copy[after_copy_lenght] = '\0';

    va_start(args, times);

    int i;
    for (i = 0; i < times; i++) {
        key_value = va_arg(args, CharsBlock);

        char *ptr = block_copy;

        if (!key_value.start_addr && !key_value.end_addr) {
            while (ptr < block_copy_end) {
                *start = *ptr;

                start++;
                ptr++;
            }

            continue;
        } else {
            uint8_t inside = 0;
            while (ptr < block_copy_end) {
                if (strncmp(ptr, FOR_OPENING_TAG__START, strlen(FOR_OPENING_TAG__START)) == 0) {
                    inside++;
                }

                if (strncmp(ptr, FOR_CLOSING_TAG, strlen(FOR_CLOSING_TAG)) == 0) {
                    if (inside > 0) {
                        inside--;
                    } else {
                        assert(0);
                    }
                }

                if (strncmp(ptr, VAL_OPENING_TAG__START, strlen(VAL_OPENING_TAG__START)) == 0) {
                    if (inside == 0) {
                        size_t val_name_length = 0;
                        char *val_name = ptr + strlen(VAL_OPENING_TAG__START);
                        char *tmp = val_name;

                        while (*tmp != '"') {
                            val_name_length++;
                            tmp++;
                        }

                        TagLocation val_tag = {0};
                        val_tag.start_addr = ptr;
                        val_tag.end_addr = ptr + strlen(VAL_OPENING_TAG__START) + val_name_length + strlen(VAL_SELF_CLOSING_TAG__END);

                        char buff[255];
                        memset(buff, 0, 255);
                        memcpy(buff, val_name, val_name_length);

                        char *value = find_value(buff, key_value);
                        assert(value);

                        size_t val_length = strlen(value);
                        memcpy(start, value, val_length);

                        ptr = val_tag.end_addr;
                        start += val_length;

                        continue;
                    }
                }

                *start = *ptr;

                start++;
                ptr++;
            }
        }
    }

    memcpy(start, after_copy, after_copy_lenght);
    start[after_copy_lenght] = '\0';

    free(block_copy);
    free(after_copy);

    /** Clean up memory */
    char *p = start + after_copy_lenght + 1;
    while (*p != '\0') {
        *p = '\0';
        p++;
    }

    va_end(args);

    return strlen(template);
}

/**
 * A dummy page used for testing purposes.
 */
void test_get(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    DBConnection *connection = get_available_connection(scratch_arena_raw);

    scratch_arena_data = connection->client.scratch_arena_data;
    scratch_arena_raw = scratch_arena_data->arena;

    const char *command = "SELECT * FROM app.countries WHERE id = $1 OR id = $2";
    Oid paramTypes[2] = {23, 23};
    int id1 = htonl(3);
    int id2 = htonl(23);
    const char *paramValues[2];
    paramValues[0] = (char *)&id1;
    paramValues[1] = (char *)&id2;
    int paramLengths[2] = {sizeof(id1), sizeof(id2)};
    int paramFormats[2] = {1, 1};
    int resultFormat = 0;

    if (PQsendQueryParams(connection->conn, command, 2, paramTypes, paramValues, paramLengths, paramFormats, resultFormat) == 0) {
        fprintf(stderr, "Query failed to send: %s\n", PQerrorMessage(connection->conn));
        int _conn_fd = PQsocket(connection->conn);
        printf("socket: %d\n", _conn_fd);
    }

    int _conn_fd = PQsocket(connection->conn);

    event.events = EPOLLIN | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, _conn_fd, &event);

    int index;

    if (connection->client.queued) {
        int r = setjmp(connection->client.jmp_buf);
        if (r == 0) {
            longjmp(db_ctx, 1);
        }

        index = from_index(r);
    } else {
        int r = setjmp(connection->client.jmp_buf);
        if (r == 0) {
            longjmp(ctx, 1);
        }

        index = from_index(r);
    }

    printf("%d", index);

    scratch_arena_data = connection_pool[index].client.scratch_arena_data;
    scratch_arena_raw = scratch_arena_data->arena;

    connection = &(connection_pool[index]);
    PGresult *result = get_result(connection);

    print_query_result(result);
    PQclear(result);

    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *template = find_value("test", p_global_arena_data->templates);

    char *template_cpy = (char *)scratch_arena_raw->current;

    memcpy(template_cpy, template, strlen(template) + 1);

    char _key_value_01[] = "name\0Table 1ajkshdkjsadhakjsdhsadkjhasjdksahdjkashdakj\0sub_name\0some long subname";
    CharsBlock key_value_01;
    key_value_01.start_addr = _key_value_01;
    key_value_01.end_addr = &(_key_value_01[sizeof(_key_value_01)]);

    char _key_value_02[] = "name\0Table 2\0sub_name\0some long subname";
    CharsBlock key_value_02;
    key_value_02.start_addr = _key_value_02;
    key_value_02.end_addr = &(_key_value_02[sizeof(_key_value_02)]);

    char _key_value_03[] = "name\0Table 3\0sub_name\0some long subname";
    CharsBlock key_value_03;
    key_value_03.start_addr = _key_value_03;
    key_value_03.end_addr = &(_key_value_03[sizeof(_key_value_03)]);

    CharsBlock empty = {0};

    render_val(template_cpy, "page_name", "Home page!");

    render_for(template_cpy, "table", 3, key_value_01, key_value_02, key_value_03);

    render_for(template_cpy, "rows", 2, empty, empty);
    render_for(template_cpy, "cells", 3, empty, empty, empty);
    render_for(template_cpy, "cells", 0);

    render_for(template_cpy, "rows", 5, empty, empty, empty, empty, empty);
    render_for(template_cpy, "cells", 4, empty, empty, empty, empty);
    render_for(template_cpy, "cells", 0);
    render_for(template_cpy, "cells", 0);
    render_for(template_cpy, "cells", 2, empty, empty);
    render_for(template_cpy, "cells", 1, empty);

    render_for(template_cpy, "rows", 3, empty, empty, empty);
    render_for(template_cpy, "cells", 1, empty);
    render_for(template_cpy, "cells", 1, empty);

    char _key_value[] = ".\0my val";
    CharsBlock key_value;
    key_value.start_addr = _key_value;
    key_value.end_addr = &(_key_value[sizeof(_key_value)]);

    render_for(template_cpy, "cells", 1, key_value);

    scratch_arena_raw->current = (char *)scratch_arena_raw->current + strlen(template_cpy) + 1;

    size_t response_length = strlen(response_headers) + strlen(template_cpy);

    char *response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, template_cpy);
    response[response_length] = '\0';

    int client_socket = scratch_arena_data->client_socket;
    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);

    /* SSL_shutdown(scratch_arena_data->ssl); */
    /* SSL_free(scratch_arena_data->ssl); */

    close(scratch_arena_data->client_socket);
    printf("Terminated - client-fd: %d\n", scratch_arena_data->client_socket);

    uint8_t was_queued = connection->client.queued;

    /* release connection for others to use */
    memset(&(connection->client), 0, sizeof(Client));

    int conn_socket = PQsocket(connection->conn);

    event.events = EPOLLOUT | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_socket, &event);

    arena_free(scratch_arena_raw);

    if (was_queued) {
        longjmp(db_ctx, 1); /** Jump back */
    } else {
        longjmp(ctx, 1); /** Jump back */
    }
}

char char_to_hex(unsigned char nibble) {
    if (nibble < 10) {
        return '0' + nibble;
    }

    if (nibble < 16) {
        return 'A' + (nibble - 10);
    }

    assert(0);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
/* URL encode function */
size_t url_encode_utf8(char **string, size_t length) {
    char *in = *string;
    static char buffer[1024];
    char *out = buffer;

    size_t new_len = 0;

    size_t i;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)in[i];

        /* Encode non-alphanumeric characters and special symbols */
        if (!isalnum(c) && c != '-' && c != '_' && c != '.' && c != '~') {
            *out++ = '%';
            *out++ = char_to_hex((c >> 4) & 0xF);
            *out++ = char_to_hex(c & 0xF);
            new_len += 3;
        } else if (c == ' ') {
            *out++ = '+';
            new_len++;
        } else {
            *out++ = c;
            new_len++;
        }
    }

    *out = '\0'; /* Null-terminate the encoded string */

    /* Copy the encoded string back to the input buffer if it fits */
    if (new_len < sizeof(buffer)) {
        strncpy(*string, buffer, new_len + 1);
    } else {
        /* Handle the case where the buffer is insufficient */
        return 0; /* Signal an error or handle it in another way */
    }

    return new_len;
}

/**
 * Decodes a URL-encoded UTF-8 string in place,
 */
size_t url_decode_utf8(char **string, size_t length) {
    char *out = *string;

    size_t new_len = 0;

    size_t i;
    for (i = 0; i < length; i++) {
        if ((*string)[i] == '%' && i + 2 < length && isxdigit((*string)[i + 1]) && isxdigit((*string)[i + 2])) {
            char c = hex_to_char((*string)[i + 1]) * 16 + hex_to_char((*string)[i + 2]);
            *out++ = c;
            i += 2;
        } else if ((*string)[i] == '+') {
            *out++ = ' ';
        } else {
            *out++ = (*string)[i];
        }

        new_len++;
    }

    memset(out, 0, length - new_len);

    return new_len;
}

char hex_to_char(unsigned char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

/**
 * Recursively searches a directory and its subdirectories to locate files with a specified
 * `extension`. If no `extension` is provided, it retrieves all files regardless of their type.
 */
char *locate_files(char *buffer, const char *base_path, const char *extension, uint8_t level, uint8_t *total_files, size_t *all_paths_length) {
    DIR *dir = opendir(base_path);
    assert(dir != NULL);

    struct dirent *entry;
    struct stat statbuf;
    size_t entry_name_length;
    char path[MAX_PATH_LENGTH];
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            sprintf(path, "%s/%s", base_path, entry->d_name);

            if (stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
                buffer = locate_files(buffer, path, extension, level + 1, total_files, all_paths_length);
            } else {
                entry_name_length = strlen(entry->d_name);
                if ((extension == NULL) || ((entry_name_length > strlen(extension)) && (strcmp(entry->d_name + entry_name_length - strlen(extension), extension) == 0))) {
                    assert(*total_files < MAX_FILES);
                    size_t path_len = strlen(path);
                    strcpy(buffer, path);
                    buffer[path_len] = '\0';
                    buffer += (path_len + 1);
                    (*all_paths_length) = (*all_paths_length) + (path_len + 1);
                    (*total_files)++;
                }
            }
        }
    }

    closedir(dir);

    return buffer;
}

/**
 * Reads a file into a dynamically allocated buffer; caller must free the buffer.
 */
void read_file(char **buffer, long *file_size, const char *absolute_file_path) {
    FILE *file = fopen(absolute_file_path, "r");
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) != -1);
    *file_size = ftell(file);
    assert(*file_size != -1);
    rewind(file);

    *buffer = (char *)malloc(*file_size * sizeof(char) + 1);
    assert(*buffer != NULL);

    size_t read_size = fread(*buffer, sizeof(char), *file_size, file);
    assert(read_size == (size_t)*file_size);

    (*buffer)[*file_size] = '\0';

    fclose(file);
}

/**
 * Locates the value corresponding to a specified key from the given HTTP request string.
 */
String find_http_request_value(const char key[], char *request) {
    String value = {0};

    if (strncmp(key, "METHOD", strlen(key)) == 0) {
        value.start_addr = request;

        char *end = request;
        while (*end != ' ') {
            end++;
        }

        value.length = end - value.start_addr;

        return value;
    }

    if (strncmp(key, "URL", strlen(key)) == 0) {
        char *ptr = request;

        while (*ptr != ' ') {
            ptr++;
        }

        ptr++;

        value.start_addr = ptr;

        char *end = ptr;
        while (*end != '?') {
            if (*end == ' ') {
                break;
            }

            end++;
        }

        value.length = end - value.start_addr;

        return value;
    }

    if (strncmp(key, "QUERY_PARAMS", strlen(key)) == 0) {
        char *ptr = request;

        while (*ptr != '\n') {
            if (*ptr == '?') {
                value.start_addr = ptr;

                break;
            }

            ptr++;
        }

        if (!value.start_addr) {
            return value;
        }

        ptr++;

        char *end = value.start_addr;
        while (*end != ' ') {
            end++;
        }

        value.length = end - value.start_addr;

        return value;
    }

    if (strncmp(key, "PROTOCOL_VERSION", strlen(key)) == 0) {
        char *ptr = request;

        uint8_t skiped_spaces = 0;
        while (*ptr != '\0') {
            if (*ptr == ' ') {
                skiped_spaces++;
            }

            if (skiped_spaces == 2) {
                break;
            }

            ptr++;
        }

        ptr++;

        value.start_addr = ptr;

        char *end_sign = "\r\n";

        char *end = ptr;
        while (*end != '\0') {
            if (strncmp(end, end_sign, strlen(end_sign)) == 0) {
                break;
            }
            end++;
        }

        value.length = end - value.start_addr;

        return value;
    }

    char *ptr = request;
    while (*ptr != '\0') {
        if (strncmp(key, ptr, strlen(key)) == 0) {
            const char str[] = ": ";
            ptr += strlen(key);

            if (strncmp(ptr, str, strlen(str)) == 0) {
                char *start = ptr + strlen(str);
                value.start_addr = start;

                char *end_sign = "\r\n";
                char *end = start;
                while (*end != '\0') {
                    if (strncmp(end, end_sign, strlen(end_sign)) == 0) {
                        break;
                    }

                    end++;
                }

                value.length = end - start;

                return value;
            }
        }

        ptr++;
    }

    return value;
}

/**
 * Finds the value associated with a given key in a dictionary.
 */
char *find_value(const char key[], Dict dict) {
    char *ptr = dict.start_addr;
    while (ptr < dict.end_addr) {
        /** Include null-terminator (+ 1) because key is a null-terminated string */
        if (strncmp(ptr, key, strlen(key) + 1) == 0) {
            ptr += strlen(ptr) + 1; /* Advance past key */
            return (ptr);
        }

        ptr += strlen(ptr) + 1; /* Advance past key */
        ptr += strlen(ptr) + 1; /* Advance past value */
    }

    return NULL;
}

void replace_slashes(char *str) {
    while (*str != '\0') {
        if (*str == '/') {
            *str = '\\'; /* Replace '/' with '\' */
        }
        str++;
    }
}

void dump_dict(Dict dict, char dir_name[]) {
    char cwd[KB(1)];
    memset(cwd, 0, KB(1));

    assert(getcwd(cwd, sizeof(cwd)) != NULL);

    char memory_dir[] = "/memory";

    assert((strlen(cwd) + strlen(memory_dir)) < KB(1));

    memcpy(&(cwd[strlen(cwd)]), memory_dir, strlen(memory_dir));

    /* Check if the directory exists */
    if (access(cwd, F_OK) == -1) {
        /* Directory doesn't exist, so create it */
        assert(mkdir(cwd, 0755) == 0);
    }

    char slash[] = "/";
    assert((strlen(cwd) + strlen(slash) + strlen(dir_name)) < KB(1));

    memcpy(&(cwd[strlen(cwd)]), slash, strlen(slash));
    memcpy(&(cwd[strlen(cwd)]), dir_name, strlen(dir_name));

    char command[KB(2)];
    sprintf(command, "rm -rf %s", cwd);
    assert(system(command) == 0);
    assert(mkdir(cwd, 0755) == 0);

    char *ptr = dict.start_addr;
    while (ptr < dict.end_addr) {
        char *key = ptr;

        char file_name[KB(2)];
        memset(file_name, 0, KB(2));
        sprintf(file_name, "%s/%s", cwd, key);

        char *name = file_name + strlen(cwd) + strlen(slash);
        replace_slashes(name);

        FILE *file = fopen(file_name, "w");
        assert(file);

        ptr += strlen(ptr) + 1;
        char *value = ptr;

        fprintf(file, "%s", value);
        ptr += strlen(ptr) + 1;

        fclose(file);
    }
}

Dict load_env_variables(const char *filepath) {
    Arena *p_global_arena_raw = _p_global_arena_raw;

    char *file_content = NULL;
    long file_size = 0;
    read_file(&file_content, &file_size, filepath);

    assert(file_size != 0);

    char *envs = (char *)p_global_arena_raw->current;
    char *p_dict_buffer = envs;

    char *line = file_content;
    char *end_of_file = file_content + file_size;

    while (line < end_of_file) { /** Basic .env file parsing. */
        char *key = NULL;
        boolean processed_key = false;

        char *value = NULL;
        boolean processed_value = false;

        char *c = line;

        /** Skip empty lines */
        if (*c == '\n') {
            goto end_of_line;
        }

        /** Skip comment line */
        if (*c == '#') {
            while (*c != '\n') {
                if (c == end_of_file) {
                    goto end_of_line;
                }

                c++;
            }

            goto end_of_line;
        }

        /** Skip whitespace characters at the beginning of the line */
        while (isspace(*c)) {
            if (c == end_of_file) {
                goto end_of_line;
            }

            c++;
        }

        /** Start processing key */
        while (!(isspace(*c)) && *c != '=') {
            if (c == end_of_file) {
                /**
                 * If we've reached the end_of_file of the file while processing
                 * the key, such variable does not have an associated value.
                 */
                assert(0);
            }

            /** Copy key into memory buffer */
            *p_dict_buffer = *c;
            if (!key) {
                key = p_dict_buffer;
            }
            p_dict_buffer++;

            c++;
        }

        *p_dict_buffer = '\0';
        p_dict_buffer++;

        processed_key = true;

        /** Skip whitespace characters after key */
        while (isspace(*c)) {
            if (c == end_of_file) {
                goto end_of_line;
            }

            c++;
        }

        /**
         * The first non-whitespace character we should find after
         * the key is the '=' after which comes the value.
         */
        if (*c != '=') {
            printf("Env variable '%s' does not have a corresponding value.\n", key);
            assert(0);
        } else {
            /** Skip '=' character */
            c++;
        }

        /** Skip whitespace characters after '=' */
        while (isspace(*c)) {
            if (c == end_of_file) {
                goto end_of_line;
            }

            c++;
        }

        /** From here we start processing value */
        while (!(isspace(*c))) {
            if (c == end_of_file) {
                if (value) {
                    printf("WARNING: EOF reached while processing value '%s' for key '%s'. Ensure value '%s' is as intended.\n", value, key, value);
                    processed_value = true;
                }

                goto end_of_line;
            }

            /** Copy value into memory buffer */
            *p_dict_buffer = *c;
            if (!value) {
                value = p_dict_buffer;
            }
            p_dict_buffer++;

            c++;
        }

        *p_dict_buffer = '\0';
        p_dict_buffer++;

        processed_value = true;

        /** Skip all character after the value and proceed to next line */
        while (*c != '\n') {
            if (c == end_of_file) {
                goto end_of_line;
            }

            c++;
        }

    end_of_line:
        line = c + 1;

        if ((processed_key == false) != (processed_value == false)) {
            /**
             * Key and value must be processed together.
             * One should not be processed without the other.
             */
            assert(0);
        }

        processed_key = false;
        processed_value = false;
    }

    p_global_arena_raw->current = p_dict_buffer + 1;

    free(file_content);
    file_content = NULL;

    Dict envs_dict = {0};
    envs_dict.start_addr = envs;
    envs_dict.end_addr = p_dict_buffer;

    return envs_dict;
}

/**
 * Loads all public files (such as .js, .css, .json) excluding HTML files, from the specified `base_path`.
 */
Dict load_public_files(const char *base_path) {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char *public_files_paths = (char *)p_global_arena_raw->current;
    uint8_t public_files_count = 0;
    size_t all_paths_length = 0;
    locate_files(public_files_paths, base_path, NULL, 0, &public_files_count, &all_paths_length);
    char *public_files_paths_end = public_files_paths + all_paths_length;
    p_global_arena_raw->current = public_files_paths_end + 1;

    char *public_files_dict = (char *)p_global_arena_raw->current;
    char *tmp_public_files_dict = public_files_dict;
    char *tmp_public_files_paths = public_files_paths;
    char extension[] = ".html";
    while (tmp_public_files_paths < public_files_paths_end) {
        /** NOT interested in html files */
        if (strncmp(tmp_public_files_paths + strlen(tmp_public_files_paths) - strlen(extension), extension, strlen(extension)) == 0) {
            tmp_public_files_paths += strlen(tmp_public_files_paths) + 1;
            continue;
        }

        char *file_content = NULL;
        long file_size = 0;
        read_file(&file_content, &file_size, tmp_public_files_paths);

        /** File path key */
        strncpy(tmp_public_files_dict, tmp_public_files_paths, strlen(tmp_public_files_paths) + 1);
        tmp_public_files_dict[strlen(tmp_public_files_paths)] = '\0';
        tmp_public_files_dict += strlen(tmp_public_files_paths) + 1;

        /** File content value */
        strncpy(tmp_public_files_dict, file_content, file_size + 1);
        tmp_public_files_dict[file_size] = '\0';
        tmp_public_files_dict += file_size + 1;

        free(file_content);
        file_content = NULL;

        tmp_public_files_paths += strlen(tmp_public_files_paths) + 1;
    }

    size_t public_files_dict_length = tmp_public_files_dict - public_files_dict;

    /** `public_files_paths` is no longer needed since file paths are now stored as keys in
     * `public_files_dict`. Shift `public_files_dict` to occupy its memory space to prevent waste. */
    char *start = public_files_paths;
    memcpy(start, public_files_dict, public_files_dict_length);
    p_global_arena_data->public_files_dict.start_addr = start;
    p_global_arena_data->public_files_dict.end_addr = start + public_files_dict_length;

    p_global_arena_raw->current = p_global_arena_data->public_files_dict.end_addr + 1;

    return p_global_arena_data->public_files_dict;
}

/**
 * A simple HTML minifier that compresses the given HTML content and stores the
 * minified result in the provided buffer. It returns the size of the minified HTML.
 */
size_t html_minify(char *buffer, char *html, size_t html_length) {
    char *start = buffer;

    char *html_end = html + html_length;

    uint8_t skip_whitespace = 0;
    while (html < html_end) {
        if (strlen(start) == 0 && isspace(*html)) {
            skip_whitespace = 1;
            html++;
            continue;
        }

        if (*html == '>') {
            char *temp = html - 1;
            if (isspace(*temp) && !skip_whitespace) {
                uint8_t i = 0;
                while (*temp) {
                    if (!isspace(*temp)) {
                        skip_whitespace = 1;
                        buffer -= i - 1;
                        break;
                    }

                    temp -= 1;
                    i++;
                }

                continue;
            }

            skip_whitespace = 1;
            goto copy_char;
        }

        if (*html == '<') {
            char *temp = html - 1;
            if (isspace(*temp) && !skip_whitespace) {
                uint8_t i = 0;
                while (*temp) {
                    if (!isspace(*temp)) {
                        skip_whitespace = 1;
                        buffer -= i - 1;
                        break;
                    }

                    temp -= 1;
                    i++;
                }

                continue;
            }

            skip_whitespace = 0;
            goto copy_char;
        }

        if (!skip_whitespace && *html == '\n') {
            html++;
            continue;
        }

        if (skip_whitespace && isspace(*html)) {
            html++;
            continue;
        }

        if (skip_whitespace && !isspace(*html)) {
            skip_whitespace = 0;
            goto copy_char;
        }

    copy_char:
        *buffer = *html;
        buffer++;

        html++;
    }

    buffer[0] = '\0';
    buffer++;

    size_t length = buffer - start;

    return length;
}

/**
 * Loads all HTML components from the specified `base_path`.
 */
Dict load_html_components(const char *base_path) {
    Arena *p_global_arena_raw = _p_global_arena_raw;

    /** Find the paths of all html files */
    char *html_files_paths = (char *)p_global_arena_raw->current;
    char extension[] = ".html";
    uint8_t html_files_count = 0;
    size_t all_paths_length = 0;
    locate_files(html_files_paths, base_path, extension, 0, &html_files_count, &all_paths_length);
    char *html_files_paths_end = html_files_paths + all_paths_length;
    p_global_arena_raw->current = html_files_paths_end + 1;

    /* A Component is an HTML snippet that may include references to other HTML snippets, i.e., it is composable */
    char *components_dict = (char *)p_global_arena_raw->current;
    char *tmp_components_dict = components_dict;
    char *tmp_filepath = html_files_paths;

    while (tmp_filepath < html_files_paths_end) {
        char *file_content = NULL;
        long file_size = 0;
        read_file(&file_content, &file_size, tmp_filepath);

        /** A .html file may contain multiple Components */
        char *tmp_file_content = file_content;
        while ((tmp_file_content = strstr(tmp_file_content, COMPONENT_DEFINITION_OPENING_TAG__START)) != NULL) { /** Process Components inside .html file. */
            /** Start processing key (component name) */
            char *component_name_start = tmp_file_content + strlen(COMPONENT_DEFINITION_OPENING_TAG__START);
            char *component_name_end = NULL;

            uint8_t component_name_length = 0;

            if ((component_name_end = strchr(component_name_start, '\"')) != NULL) {
                component_name_length = component_name_end - component_name_start;
                strncpy(tmp_components_dict, component_name_start, component_name_length);
                tmp_components_dict[component_name_length] = '\0';
                tmp_components_dict += component_name_length + 1;
            } else {
                assert(0);
            }

            /** Start processing value (component html) */
            char *html = tmp_file_content + strlen(COMPONENT_DEFINITION_OPENING_TAG__START) + (size_t)component_name_length + strlen(COMPONENT_DEFINITION_OPENING_TAG__END);

            size_t html_length = 0;
            char *ptr = html;
            while (*ptr) {
                if (strncmp(ptr, COMPONENT_DEFINITION_CLOSING_TAG, strlen(COMPONENT_DEFINITION_CLOSING_TAG)) == 0) {
                    break;
                }

                html_length++;
                ptr++;
            }

            size_t minified_html_length = html_minify(tmp_components_dict, html, html_length);

            tmp_components_dict += minified_html_length;
            tmp_file_content++;
        }

        free(file_content);
        file_content = NULL;

        tmp_filepath += strlen(tmp_filepath) + 1;
    }

    size_t components_dict_length = tmp_components_dict - components_dict;

    /** `html_files_paths` is no longer needed since file paths are now stored as keys in
     * `components_dict`. Shift `components_dict` to occupy its memory space to prevent waste. */
    char *start = html_files_paths;
    memcpy(start, components_dict, components_dict_length);
    Dict html_raw_components_dict = {0};
    html_raw_components_dict.start_addr = start;
    html_raw_components_dict.end_addr = start + components_dict_length;

    p_global_arena_raw->current = html_raw_components_dict.end_addr + 1;

    return html_raw_components_dict;
}

uint8_t get_dict_size(Dict dict) {
    size_t size = 0;

    char *ptr = dict.start_addr;
    while (ptr < dict.end_addr) {
        ptr += strlen(ptr) + 1; /* Advance past key */
        ptr += strlen(ptr) + 1; /* Advance past value */
        size++;
    }

    return size;
}

/**
 * Loads and resolves all HTML components along with their imports from the specified `base_path`.
 */
Dict load_templates(const char *base_path) {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    Dict html_raw_components = load_html_components(base_path);

    uint8_t i;

    /* A template is essentially a Component that has been compiled with all its imports. */
    char *templates_dict = (char *)p_global_arena_raw->current;
    char *tmp_templates_dict = templates_dict;

    char *components = html_raw_components.start_addr;
    char *tmp_components = components;

    uint8_t components_count = get_dict_size(html_raw_components);

    for (i = 0; i < components_count; i++) { /** Compile Components. */
        uint8_t html_template_name_length = (uint8_t)strlen(tmp_components);
        strncpy(tmp_templates_dict, tmp_components, html_template_name_length);
        tmp_templates_dict[html_template_name_length] = '\0';

        tmp_templates_dict += html_template_name_length + 1;

        tmp_components += strlen(tmp_components) + 1; /* Advance pointer to component markdown */

        size_t component_markdown_length = strlen(tmp_components);
        strncpy(tmp_templates_dict, tmp_components, component_markdown_length);
        tmp_templates_dict[component_markdown_length] = '\0';

        char *template_start = tmp_templates_dict;

        char *component_import_opening_tag = tmp_templates_dict;
        while ((component_import_opening_tag = strstr(component_import_opening_tag, COMPONENT_IMPORT_OPENING_TAG__START)) != NULL) { /** Resolve Component imports. */
            tmp_templates_dict += (component_import_opening_tag - tmp_templates_dict);

            char *import_name_start = component_import_opening_tag + strlen(COMPONENT_IMPORT_OPENING_TAG__START);
            char *tmp_import_name = import_name_start;

            uint8_t imported_name_length = 0;

            while (*tmp_import_name) {
                if (strncmp(tmp_import_name, OPENING_COMPONENT_IMPORT_TAG_SELF_CLOSING_END, strlen(OPENING_COMPONENT_IMPORT_TAG_SELF_CLOSING_END)) == 0) { /** Import doesn't contain "slots" */
                    imported_name_length = tmp_import_name - import_name_start;

                    char *tmp_components_j = components;

                    uint8_t j;
                    for (j = 0; j < components_count; j++) {
                        if (strncmp(tmp_components_j, import_name_start, imported_name_length) == 0) {
                            tmp_components_j += strlen(tmp_components_j) + 1; /* Advance pointer to component markdown */

                            uint8_t import_statement_length = (uint8_t)strlen(COMPONENT_IMPORT_OPENING_TAG__START) + imported_name_length + (uint8_t)strlen(OPENING_COMPONENT_IMPORT_TAG_SELF_CLOSING_END);
                            size_t component_markdown_length = strlen(tmp_components_j);

                            size_t len = strlen(tmp_templates_dict + import_statement_length);
                            memmove(tmp_templates_dict + component_markdown_length, tmp_templates_dict + import_statement_length, len);
                            char *ptr = tmp_templates_dict + component_markdown_length + len;
                            ptr[0] = '\0';
                            ptr++;
                            while (*ptr) {
                                size_t str_len = strlen(ptr);
                                memset(ptr, 0, str_len);
                                ptr += str_len + 1;
                            }

                            memcpy(tmp_templates_dict, tmp_components_j, component_markdown_length);

                            break; /** We have successfully found the component related to
                                    * the import and incorporated it into the template. */
                        }

                        /** This is not the component we are looking for... */
                        tmp_components_j += strlen(tmp_components_j) + 1; /* Advance past the component name */
                        tmp_components_j += strlen(tmp_components_j) + 1; /* Advance past the component markdown */

                        if ((j + 1) == components_count) {
                            printf("didn't find component\n");
                            assert(0);
                        }
                    }

                    /**
                     * The component we imported may contain additional imports. Reset the pointer to
                     * the start of the HTML template to check for imports from the beginning again.
                     */
                    tmp_templates_dict = template_start;

                    break;
                }

                if (strncmp(tmp_import_name, COMPONENT_IMPORT_OPENING_TAG__END, strlen(COMPONENT_IMPORT_OPENING_TAG__END)) == 0) { /** Import contain "slots" */
                    imported_name_length = tmp_import_name - import_name_start;

                    char *tmp_components_j = components;

                    uint8_t j;
                    for (j = 0; j < components_count; j++) {
                        if (strncmp(tmp_components_j, import_name_start, imported_name_length) == 0) {
                            tmp_components_j += strlen(tmp_components_j) + 1; /* Advance pointer to component markdown */

                            resolve_slots(tmp_components_j, component_import_opening_tag, &tmp_templates_dict);

                            break; /** We have successfully found the component related to
                                    * the import and incorporated it into the template. */
                        }

                        tmp_components_j += strlen(tmp_components_j) + 1; /* Advance past component name */
                        tmp_components_j += strlen(tmp_components_j) + 1; /* Advance past component markdown */

                        if ((j + 1) == components_count) {
                            printf("didn't find component\n");
                            assert(0);
                        }
                    }

                    break;
                }

                tmp_import_name++;
            }
        }

        tmp_components += strlen(tmp_components) + 1; /* Advance pointer to component name */
        tmp_templates_dict += strlen(tmp_templates_dict) + 1;
    }

    size_t templates_dict_length = tmp_templates_dict - templates_dict;

    /** `html_raw_components` is no longer needed since they have been compiled
     * into the `templates_dict`. Shift `templates_dict` to occupy its memory
     * space to prevent waste. */
    char *start = html_raw_components.start_addr;
    memcpy(start, templates_dict, templates_dict_length);
    p_global_arena_data->templates.start_addr = start;
    p_global_arena_data->templates.end_addr = start + templates_dict_length;

    p_global_arena_raw->current = p_global_arena_data->templates.end_addr + 1;

    return p_global_arena_data->templates;
}

Socket *create_server_socket(uint16_t port) {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(server_fd != -1);

    int server_fd_flags = fcntl(server_fd, F_GETFL, 0);
    assert(fcntl(server_fd, F_SETFL, server_fd_flags | O_NONBLOCK) != -1);

    int server_fd_optname = 1;
    assert(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &server_fd_optname, sizeof(int)) != -1);

    /** Configure server address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;         /** IPv4 */
    server_addr.sin_port = htons(port);       /** Convert the port number from host byte order to network byte order (big-endian) */
    server_addr.sin_addr.s_addr = INADDR_ANY; /** Listen on all available network interfaces (IPv4 addresses) */

    assert(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != -1);

    assert(listen(server_fd, MAX_CLIENT_CONNECTIONS) != -1);

    Socket *server_socket = arena_alloc(p_global_arena_raw, sizeof(Socket));
    server_socket->fd = server_fd;
    server_socket->type = SERVER_SOCKET;

    p_global_arena_data->socket = server_socket;

    return p_global_arena_data->socket;
}

void create_connection_pool(Dict envs) {
    uint8_t i;
    for (i = 0; i < CONNECTION_POOL_SIZE; i++) {
        char *database = find_value("DB_NAME", envs);
        char *user = find_value("DB_USER", envs);
        char *password = find_value("PASSWORD", envs);
        char *host = find_value("HOST", envs);

        const char *keys[] = {"dbname", "user", "password", "host", NULL};
        const char *values[5];
        values[0] = database;
        values[1] = user;
        values[2] = password;
        values[3] = host;
        values[4] = NULL;

        connection_pool[i].conn = PQconnectStartParams(keys, values, 0);

        assert(PQstatus(connection_pool[i].conn) != CONNECTION_BAD); /** Connection failed */

        PQsetnonblocking(connection_pool[i].conn, 1);

        connection_pool[i].type = DB_SOCKET;
        connection_pool[i].index = i;

        int fd = PQsocket(connection_pool[i].conn);

        event.events = EPOLLOUT;
        event.data.ptr = &(connection_pool[i]);
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
    }

    int count = 0;
    while (count < CONNECTION_POOL_SIZE) {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, BLOCK_EXECUTION);
        assert(nfds != -1);

        for (i = 0; i < nfds; i++) {
            FDType *type = (FDType *)events[i].data.ptr;

            if (*type == DB_SOCKET) {
                DBConnection *connection = (DBConnection *)type;
                PostgresPollingStatusType poll_status = PQconnectPoll(connection->conn);

                int fd = PQsocket(connection->conn);

                if (poll_status == PGRES_POLLING_READING) {
                    event.events = EPOLLIN;
                    event.data.ptr = connection;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
                } else if (poll_status == PGRES_POLLING_WRITING) {
                    event.events = EPOLLOUT;
                    event.data.ptr = connection;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
                } else if (poll_status == PGRES_POLLING_OK) {
                    printf("Connection established!\n");
                    count++;
                    break;
                } else {
                    fprintf(stderr, "Connection failed: %s\n", PQerrorMessage(connection->conn));
                    break;
                }
            }
        }
    }
}

/**
 * Initializes a new memory arena, with the arena header stored at the beginning of the allocated memory block.
 */
Arena *arena_init(size_t size) {
    Arena *arena = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(arena != NULL);

    memset(arena, 0, size);

    arena->size = size;
    arena->start = arena;
    arena->current = (uint8_t *)arena + sizeof(Arena);

    return arena;
}

/**
 * Allocates memory from the arena and advances the current pointer by the requested size.
 */
void *arena_alloc(Arena *arena, size_t size) {
    if ((uint8_t *)arena->current + size > (uint8_t *)arena->start + arena->size) {
        assert(0);
    }

    void *ptr = arena->current;
    arena->current = (uint8_t *)arena->current + size;

    return ptr;
}

/**
 *  Resets the arena allocator by clearing its used memory and resetting the current pointer.
 */
void arena_reset(Arena *arena, size_t arena_header_size) {
    uint8_t *start = (uint8_t *)arena->start + arena_header_size;

    size_t set_bytes = (uint8_t *)arena->current - start;
    memset(start, 0, set_bytes);

    arena->current = start;
}

void arena_free(Arena *arena) {
    if (munmap(arena->start, arena->size) == -1) {
        assert(0);
    }
}

/**
 * Encapsulates boilerplate logic for printing the result of a PostgreSQL query in a formatted table.
 */
void print_query_result(PGresult *query_result) {
    PQprintOpt options = {0};          /* Initialize to zero to avoid garbage values */
    options.header = 1;                /* Print headers */
    options.align = 1;                 /* Align output nicely */
    options.html3 = 0;                 /* Don't print HTML table format */
    options.expanded = 0;              /* Normal table format */
    options.pager = 0;                 /* Don't use pager */
    options.fieldSep = " | ";          /* Field separator */
    options.tableOpt = "border=1";     /* Table option if using HTML */
    options.caption = "Query Results"; /* Caption for the table */

    PQprint(stdout, query_result, &options);
}

void release_request_resources_and_exit(Arena *scratch_arena_raw, DBConnection *connection) {
    uint8_t was_request_queued = connection->client.queued;

    /* Set connection as unused */
    memset(&(connection->client), 0, sizeof(Client));

    /** Set connection available for write */
    int conn_socket = PQsocket(connection->conn);
    event.events = EPOLLOUT | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_socket, &event);

    arena_free(scratch_arena_raw);

    if (was_request_queued) {
        longjmp(db_ctx, 1);
    }

    longjmp(ctx, 1);
}

void sigint_handler(int signo) {
    if (signo == SIGINT) {
        printf("\nReceived SIGINT, exiting program...\n");
        keep_running = 0;
    }
}

void save_stack_state(Stack stack) {
    stack.stack_buffer = (char *)malloc(stack.stack_size);
    if (stack.stack_buffer) {
        memcpy(stack.stack_buffer, stack.stack_ptr, stack.stack_size);
    }
}

void restore_stack_state(Stack stack) {
    if (stack.stack_buffer) {
        memcpy(stack.stack_ptr, stack.stack_buffer, stack.stack_size);
    }
}