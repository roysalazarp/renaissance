#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libpq-fe.h>
#include <linux/limits.h>
#include <netinet/in.h>
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

/*
+-----------------------------------------------------------------------------------+
|                                     defines                                       |
+-----------------------------------------------------------------------------------+
*/

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

#define MAX_PATH_LENGTH 200
#define MAX_FILES 20
#define MAX_CONNECTIONS 100 /** ?? */
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

#define OPENING "{{"
#define CLOSING "}}"

#define URL(path) path "\x20"

/*
+-----------------------------------------------------------------------------------+
|                                     structs                                       |
+-----------------------------------------------------------------------------------+
*/

typedef enum { FOR_START, FOR_END } TokenType;

typedef enum { POINT_BEFORE, POINT_AFTER } CharPointer;

typedef enum { SERVER_SOCKET, CLIENT_SOCKET, DB_SOCKET } FDType;

typedef struct {
    FDType type;
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
    uint8_t *start_addr;
    uint8_t *end_addr;
} MemBlock;

typedef struct {
    char *start_addr;
    char *end_addr;
} CharsBlock;

typedef struct {
    char *before;
    char *after;
} BlockId;

typedef struct {
    char *db_connection_string;
    CharsBlock envs;
    Socket *socket;
    struct {
        CharsBlock paths;
        CharsBlock file_dict;
    } public;
    struct {
        struct {
            CharsBlock paths;
            uint8_t count;
            CharsBlock component_dict;
        } raw;
        CharsBlock component_dict;
    } html;
} GlobalArenaDataLookup;

typedef struct {
    Arena *arena;
    int client_socket;
    CharsBlock request;
    CharsBlock response;
    void *local;
} ScratchArenaDataLookup;

typedef struct {
    int fd;
    Arena *scratch_arena_raw;
    ScratchArenaDataLookup *scratch_arena_data;
    jmp_buf jmp_buf;
    uint8_t queued;
} Client;

typedef struct {
    FDType type;
    uint8_t index;
    PGconn *conn;
    Client client;
} DBConnection;

typedef struct {
    uint8_t index;
    Client client;
} QueuedRequest;

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
CharsBlock load_public_files(const char *base_path);
CharsBlock load_html_components(const char *base_path);
CharsBlock resolve_html_components_imports();
void resolve_slots(char *component_markdown, char *import_statement, char **templates);
size_t render(char *template, char *scope, int times, ...);
BlockId find_token(char *string, char *keyword, TokenType token_type);
size_t html_minify(char *buffer, char *html, size_t html_length);

/** Connection */
char *load_db_connection_string(const char *filepath);
void create_connection_pool(const char *conn_info);
DBConnection *get_connection(Arena *scratch_arena_raw);
QueuedRequest *put_in_queue(Arena *scratch_arena_raw);
void print_query_result(PGresult *query_result);

/** Request handlers */
void router(Arena *scratch_arena_raw);
void home_get(Arena *scratch_arena_raw);
void not_found(int client_socket);
void public_get(Arena *scratch_arena_raw, String url);
void view_get(Arena *scratch_arena_raw, char *view);
void sign_up_get(Arena *scratch_arena_raw);
void sign_up_create_user_post(Arena *scratch_arena_raw);
void auth_validate_email_post(Arena *scratch_arena_raw);

/** Request utils */
String find_http_request_value(const char key[], char *request);
uint16_t string_to_uint16(const char *str);
char *find_body(CharsBlock request);
CharsBlock parse_body_value(const char key_name[], char *request_body);
char *file_content_type(Arena *scratch_arena_raw, const char *path);
size_t url_decode_utf8(char **string, size_t length);

/** Utils */
CharsBlock load_env_variables(const char *filepath);
void read_file(char **buffer, long *file_size, char *absolute_file_path);
char *locate_files(char *buffer, const char *base_path, const char *extension, uint8_t level, uint8_t *total_html_files, size_t *all_paths_length);
char *get_value(const char key[], size_t key_length, CharsBlock block);
char hex_to_char(char c);

/*
+-----------------------------------------------------------------------------------+
|                                     globals                                       |
+-----------------------------------------------------------------------------------+
*/

Arena *_p_global_arena_raw;
GlobalArenaDataLookup *_p_global_arena_data;

int epoll_fd;
int nfds;
struct epoll_event events[MAX_EVENTS];
struct epoll_event event;

#define to_index(i) (i + 1)
#define from_index(i) (i - 1)

DBConnection connection_pool[CONNECTION_POOL_SIZE];
QueuedRequest queue[MAX_CONNECTIONS];

jmp_buf ctx;
jmp_buf db_ctx;

int h_count;

/*
+-----------------------------------------------------------------------------------+
|                                       code                                        |
+-----------------------------------------------------------------------------------+
*/

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
int main() {
    int i;

    _p_global_arena_raw = arena_init(PAGE_SIZE * 20);

    /** To look up data stored in arena */
    _p_global_arena_data = (GlobalArenaDataLookup *)arena_alloc(_p_global_arena_raw, sizeof(GlobalArenaDataLookup));

    CharsBlock envs = load_env_variables("./.env");

    const char *public_base_path = get_value("PUBLIC_FOLDER", sizeof("PUBLIC_FOLDER"), envs);
    CharsBlock public_files = load_public_files(public_base_path);

    const char *html_base_path = get_value("TEMPLATES_FOLDER", sizeof("TEMPLATES_FOLDER"), envs);
    CharsBlock html_raw_components = load_html_components(html_base_path);

    CharsBlock html_components = resolve_html_components_imports(); /** TODO: Review the code inside this function */

    epoll_fd = epoll_create1(0);
    assert(epoll_fd != -1);

    uint16_t port = 8080;
    Socket *server_socket = create_server_socket(port);
    int server_fd = server_socket->fd;

    event.events = EPOLLIN;
    event.data.ptr = server_socket;
    assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) != -1);

    printf("Server listening on port: %d...\n", port);

    char *connection_string = load_db_connection_string("./db_connection_params");
    create_connection_pool(connection_string);

    struct sockaddr_in client_addr; /** Why is this needed ?? */
    socklen_t client_addr_len = sizeof(client_addr);

    while (1) {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, BLOCK_EXECUTION);
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

                        printf("Initiated - client-fd: %d\n", client_fd);

                        /** Allocate memory for handling client request */
                        Arena *scratch_arena_raw = arena_init(PAGE_SIZE * 10);
                        Socket *client_socket_info = (Socket *)arena_alloc(scratch_arena_raw, sizeof(Socket));
                        client_socket_info->fd = client_fd;
                        client_socket_info->type = CLIENT_SOCKET;

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

                case CLIENT_SOCKET: {
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
                    if (events[i].events & EPOLLIN) { /** DB socket (aka connection) ready for read */
                        DBConnection *connection = (DBConnection *)socket_info;

                        /** The connection should belong to a client fd (aka request) */
                        assert(connection->client.fd != 0);

                        /** Go back to where you attempted to read the result of a
                         * query but jumped out since we are not supposed to wait
                         * for response to be ready. Pass index to restore request
                         * state through connection pool */
                        longjmp(connection->client.jmp_buf, to_index(connection->index));
                    } else if (events[i].events & EPOLLOUT) { /** DB socket (aka connection) is ready for write */
                        DBConnection *connection = (DBConnection *)socket_info;

                        QueuedRequest *request = NULL;

                        int j;
                        for (j = 0; j < MAX_CONNECTIONS; j++) {
                            if (queue[j].client.fd != 0) {
                                /** First in the queue waiting for connection */
                                request = &(queue[j]);

                                break;
                            }
                        }

                        if (request) {
                            connection->client = request->client;
                            memcpy(&(connection->client), &(request->client), sizeof(Client));
                            memset(&(request->client), 0, sizeof(Client));

                            if (setjmp(db_ctx) == 0) {
                                longjmp(connection->client.jmp_buf /* This will jump to queue find loop */, to_index(connection->index));
                            }
                        }

                        /** We don't do anything here since the connection pool
                         * already only allow us to use free connections (aka db sockets ready for write) */
                    }

                    break;
                }

                default: {
                    /* TODO */
                    break;
                }
            }
        }
    }

    close(server_fd);

    arena_free(_p_global_arena_raw);

    return 0;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
uint16_t string_to_uint16(const char *str) {
    char *endptr;
    errno = 0;
    unsigned long ul = strtoul(str, &endptr, 10);

    if (errno != 0) {
        perror("strtoul");
        return 0;
    }

    if (*endptr != '\0') {
        fprintf(stderr, "Trailing characters after number: %s\n", endptr);
        return 0;
    }

    if (ul > UINT16_MAX) {
        fprintf(stderr, "Value out of range for uint16_t\n");
        return 0;
    }

    return (uint16_t)ul;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void router(Arena *scratch_arena_raw) {
    int i;

    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    int client_socket = scratch_arena_data->client_socket;

    printf("Handling - client-fd: %d\n", client_socket);

    char *request = (char *)scratch_arena_raw->current;
    scratch_arena_data->request.start_addr = scratch_arena_raw->current;

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
            /*
            printf("Error: %s\n", strerror(errno));
            */

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (read_stream > 0) {
                    break;
                }

                longjmp(ctx, 1);
            }
        }

        if (incomming_stream_size <= 0) {
            /** FIX IMPORTANT: Make client_socket non-blocking, otherwise it will block when client request contains 0 bytes */
            printf("fd %d - Empty request\n", client_socket);
            return;
        }

        /** decode */
        /*
        incomming_stream_size = (ssize_t)url_decode_utf8(&advanced_request_ptr, (size_t)incomming_stream_size);
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
    scratch_arena_data->request.end_addr = (char *)scratch_arena_raw->current - 1;

    if (strlen(scratch_arena_data->request.start_addr) == 0) {
        printf("Request is empty\n");

        close(client_socket);
        return;
    }

    String url = find_http_request_value("URL", scratch_arena_data->request.start_addr);

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

    if (strncmp(url.start_addr, URL("/auth"), strlen(URL("/auth"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            view_get(scratch_arena_raw, "auth");
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/auth/validate-email"), strlen(URL("/auth/validate-email"))) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            auth_validate_email_post(scratch_arena_raw);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/sign-up"), strlen(URL("/sign-up"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            sign_up_get(scratch_arena_raw);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/sign-up/create-user"), strlen(URL("/sign-up/create-user"))) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            sign_up_create_user_post(scratch_arena_raw);
            return;
        }
    }

    not_found(client_socket);
    return;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
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
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void sign_up_create_user_post(Arena *scratch_arena_raw) {
    /** Process signup */

    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    char *body = find_body(scratch_arena_data->request);

    CharsBlock email = parse_body_value("email", body);
    CharsBlock password = parse_body_value("password", body);
    CharsBlock repeat_password = parse_body_value("repeat_password", body);

    printf("%s\n", body);

    printf("%.*s\n", (int)(email.end_addr - email.start_addr), email.start_addr);
    /** TODO: Validate whether email satisfies required format */
    /** TODO: Validate whether email already exists in the db */

    printf("%.*s\n", (int)(password.end_addr - password.start_addr), password.start_addr);
    printf("%.*s\n", (int)(repeat_password.end_addr - repeat_password.start_addr), repeat_password.start_addr);

    int client_socket = scratch_arena_data->client_socket;

    char response[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

    if (send(client_socket, response, strlen(response), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(client_socket);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
char *find_body(CharsBlock request) {
    char *body = request.start_addr;

    while (body < request.end_addr) {
        char header_headers_end[] = "\r\n\r\n";
        if (strncmp(body, header_headers_end, strlen(header_headers_end)) == 0) {
            body += strlen(header_headers_end);

            break;
        }

        body++;
    }

    return body;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
CharsBlock parse_body_value(const char key_name[], char *request_body) {
    CharsBlock value = {0};
    value.start_addr = request_body;

    char *p = request_body;
    char *end = request_body + strlen(request_body) + 1;

    while (value.start_addr < end) {
        if (strncmp(value.start_addr, key_name, strlen(key_name)) == 0) {
            char *passed_key = value.start_addr + strlen(key_name);

            if (passed_key[0] == '=') {
                passed_key++;
                value.start_addr = passed_key;
                break;
            }
        }

        value.start_addr++;
    }

    value.end_addr = value.start_addr;

    while (value.end_addr < end) {
        if (value.end_addr[0] == '&' || value.end_addr[0] == '\0') {
            break;
        }

        value.end_addr++;
    }

    return value;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void view_get(Arena *scratch_arena_raw, char *view) {
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    int client_socket = scratch_arena_data->client_socket;

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *template = get_value(view, strlen(view), p_global_arena_data->html.component_dict);

    size_t response_length = strlen(response_headers) + strlen(template);

    char *response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, template);
    response[response_length] = '\0';

    if (send(client_socket, response, strlen(response), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(client_socket);

    arena_free(scratch_arena_raw);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
DBConnection *get_connection(Arena *scratch_arena_raw) {
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    int i;

    for (i = 0; i < CONNECTION_POOL_SIZE; i++) {
        if (connection_pool[i].client.fd == 0) {

            connection_pool[i].client.fd = scratch_arena_data->client_socket;
            connection_pool[i].client.scratch_arena_raw = scratch_arena_raw;
            connection_pool[i].client.scratch_arena_data = scratch_arena_data;

            DBConnection *connection = &(connection_pool[i]);

            return connection;
        }
    }

    return NULL;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
QueuedRequest *put_in_queue(Arena *scratch_arena_raw) {
    int i;

    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (queue[i].client.fd == 0) {
            /* Available spot in the queue */

            queue[i].client.fd = scratch_arena_data->client_socket;
            queue[i].client.scratch_arena_raw = scratch_arena_raw;
            queue[i].client.scratch_arena_data = scratch_arena_data;
            queue[i].client.queued = 1;

            QueuedRequest *queued = &(queue[i]);

            return queued;
        }
    }

    assert(0);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void auth_validate_email_post(Arena *scratch_arena_raw) {
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    DBConnection *connection = get_connection(scratch_arena_raw);

    if (connection == NULL) {
        QueuedRequest *queued = put_in_queue(scratch_arena_raw);

        int r = setjmp(queued->client.jmp_buf);
        if (r == 0) {
            longjmp(ctx, 1);
        }

        int index = from_index(r);

        connection = &(connection_pool[index]);

        scratch_arena_data = connection->client.scratch_arena_data;
        scratch_arena_raw = scratch_arena_data->arena;
    }

    assert(connection != NULL);

    char *body = find_body(scratch_arena_data->request);

    /** IMPORTANT: Test with email test@example.com */

    CharsBlock encoded_email = parse_body_value("email", body);
    size_t encoded_email_length = encoded_email.end_addr - encoded_email.start_addr;

    char *email = (char *)arena_alloc(scratch_arena_raw, encoded_email_length);
    memcpy(email, encoded_email.start_addr, encoded_email_length);
    url_decode_utf8(&email, encoded_email_length);

    const char *command = "SELECT * FROM app.users WHERE email = $1";
    Oid paramTypes[1] = {25};
    const char *paramValues[1];
    paramValues[0] = email;
    int paramLengths[1] = {0};
    int paramFormats[1] = {0};
    int resultFormat = 0;

    if (PQsendQueryParams(connection->conn, command, 1, paramTypes, paramValues, paramLengths, paramFormats, resultFormat) == 0) {
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

    scratch_arena_data = connection_pool[index].client.scratch_arena_data;
    scratch_arena_raw = scratch_arena_data->arena;

    connection = &(connection_pool[index]);

    while (PQisBusy(connection->conn)) {
        int _conn_fd = PQsocket(connection->conn);

        printf("busy socket: %d\n", _conn_fd);

        if (!PQconsumeInput(connection->conn)) {
            fprintf(stderr, "PQconsumeInput failed: %s\n", PQerrorMessage(connection->conn));
        }
    }

    PGresult *res;
    while ((res = PQgetResult(connection->conn)) != NULL) {
        if (PQresultStatus(res) != PGRES_TUPLES_OK && PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Query failed: %s\n", PQerrorMessage(connection->conn));
            PQclear(res);
            break;
        }

        print_query_result(res);

        PQclear(res);
    }

    int client_socket = scratch_arena_data->client_socket;

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *template = get_value("login-form", sizeof("login-form"), p_global_arena_data->html.component_dict);

    size_t response_length = strlen(response_headers) + strlen(template);

    char *response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, template);
    response[response_length] = '\0';

    if (send(client_socket, response, strlen(response), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(scratch_arena_data->client_socket);

    uint8_t was_queued = connection->client.queued;

    /* release connection for others to use */
    memset(&(connection->client), 0, sizeof(Client));

    int conn_fd = PQsocket(connection->conn);

    event.events = EPOLLOUT | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_fd, &event);

    arena_free(scratch_arena_raw);

    if (was_queued) {
        longjmp(db_ctx, 1); /** Jump back */
    } else {
        longjmp(ctx, 1); /** Jump back */
    }
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void sign_up_get(Arena *scratch_arena_raw) {
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    int client_socket = scratch_arena_data->client_socket;

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *template = get_value("sign-up", sizeof("sign-up"), p_global_arena_data->html.component_dict);

    size_t response_length = strlen(response_headers) + strlen(template);

    char *response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, template);
    response[response_length] = '\0';

    if (send(client_socket, response, strlen(response), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(client_socket);

    arena_free(scratch_arena_raw);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
char *file_content_type(Arena *scratch_arena_raw, const char *path) {
    char *path_end = path + strlen(path);

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

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void public_get(Arena *scratch_arena_raw, String url) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    int client_socket = scratch_arena_data->client_socket;

    const char *base_path = get_value("PUBLIC_FOLDER", sizeof("PUBLIC_FOLDER"), p_global_arena_data->envs);

    char *path = (char *)arena_alloc(scratch_arena_raw, sizeof('.') + url.length);
    char *tmp_path = path;
    tmp_path[0] = '.';
    tmp_path++;
    strncpy(tmp_path, url.start_addr, url.length);

    char *public_file_type = file_content_type(scratch_arena_raw, path);
    char *content = get_value(path, strlen(path), p_global_arena_data->public.file_dict);

    char *res = (char *)scratch_arena_raw->current;
    scratch_arena_data->response.start_addr = res;

    sprintf(res,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n\r\n"
            "%s",
            public_file_type, content);

    char *res_end = res;
    while (1) {
        if (*res_end == 0) {
            break;
        }

        res_end++;
    }

    scratch_arena_data->response.end_addr = res_end;
    scratch_arena_raw->current = res_end + 1;

    if (send(client_socket, res, strlen(res), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(client_socket);

    arena_free(scratch_arena_raw);
}

BlockId find_token(char *string, char *keyword, TokenType token_type) {
    BlockId token = {0};

    char *block = NULL;

    char *for_start = " for";
    char *for_end = " end-for";

    char *type;

    if (token_type == FOR_START) {
        type = for_start;
    } else if (token_type == FOR_END) {
        type = for_end;
    } else {
        assert(0);
    }

    char *tmp_template = string;
    while (*tmp_template != '\0') {
        if (strncmp(tmp_template, keyword, strlen(keyword)) == 0) {
            char *before_block_name = tmp_template - 1;
            char *after_block_name = tmp_template + strlen(keyword);

            while (before_block_name > string) {
                if (isspace(*before_block_name)) {
                    before_block_name--;
                    continue;
                } else if (strncmp(before_block_name + 1 - strlen(type), type, strlen(type)) == 0) {
                    printf("Previous word IS \"for\"\n");
                    char *before_for = before_block_name + 1 - strlen(type);

                    while (before_for > string) {
                        if (isspace(*before_for)) {
                            before_for--;
                            continue;
                        } else if (strncmp(before_for + 1 - strlen("{{"), "{{", strlen("{{")) == 0) {
                            printf("Previous word IS \"{{\"\n");

                            while (*after_block_name != '\0') {
                                if (isspace(*after_block_name)) {
                                    after_block_name++;
                                    continue;
                                } else if (strncmp(after_block_name, "}}", strlen("}}")) == 0) {
                                    printf("Next after block name IS \"}}\"\n");

                                    token.before = before_for + 1 - strlen("{{");
                                    token.after = after_block_name + strlen("}}");

                                    goto exit;
                                } else {
                                    printf("Next after block name IS NOT \"}}\"\n");
                                    break;
                                }
                            }
                        } else {
                            printf("Previous word IS NOT \"{{\"\n");
                            break;
                        }
                    }
                } else {
                    printf("Previous word IS NOT \"for\"\n");
                    break;
                }
            }
        }

        tmp_template++;
    }

exit:
    return token;
}

size_t render(char *template, char *block_name, int times, ...) {
    va_list args;
    CharsBlock key_value = {0};

    BlockId block_start = find_token(template, block_name, FOR_START);
    BlockId block_end = find_token(template, block_name, FOR_END);

    size_t block_length = block_end.before - block_start.after;

    char *block_copy = (char *)malloc((block_length + 1) * sizeof(char));
    memcpy(block_copy, block_start.after, block_length);
    block_copy[block_length] = '\0';
    char *block_copy_end = block_copy + block_length;

    char *start = block_start.before;
    char *after = block_end.after;

    size_t after_copy_lenght = strlen(after);
    char *after_copy = (char *)malloc((after_copy_lenght + 1) * sizeof(char));
    memcpy(after_copy, after, after_copy_lenght);
    after_copy[after_copy_lenght] = '\0';

    size_t room = block_end.after - block_start.before;

    va_start(args, times);

    int i;
    for (i = 0; i < times; i++) {
        key_value = va_arg(args, CharsBlock);

        char *tmp_block_copy = block_copy;

        while (tmp_block_copy < block_copy_end) {
            if (strncmp(tmp_block_copy, "{{", strlen("{{")) == 0) {
                char *token = tmp_block_copy + strlen("{{");

                char *token_start;
                char *token_end;

                while (isspace(*token)) {
                    token++;
                }

                token_start = token;

                while (!isspace(*token)) {
                    token++;
                }

                token_end = token;

                while (isspace(*token)) {
                    token++;
                }

                if (strncmp(token, "}}", strlen("}}")) == 0) {
                    token += strlen("}}");
                    size_t length = token_end - token_start;

                    if (key_value.start_addr && key_value.end_addr) {
                        char *value = get_value(token_start, length, key_value);

                        if (value) {
                            size_t val_length = strlen(value);
                            memcpy(start, value, val_length);

                            tmp_block_copy = token;
                            start += val_length;

                            printf("\n");
                            continue;
                        }
                    }
                }
            }

            *start = *tmp_block_copy;

            start++;
            tmp_block_copy++;
        }

        after = start;
    }

    memcpy(start, after_copy, after_copy_lenght);
    start[after_copy_lenght] = '\0';

    /** Clean up memory */
    char *p = start + after_copy_lenght + 1;
    while (*p != '\0') {
        *p = '\0';
    }

    printf("\n");

    va_end(args);

    return strlen(template);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void home_get(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(Socket)));

    DBConnection *connection = get_connection(scratch_arena_raw);

    if (connection == NULL) {
        QueuedRequest *queued = put_in_queue(scratch_arena_raw);

        int r = setjmp(queued->client.jmp_buf);
        if (r == 0) {
            longjmp(ctx, 1);
        }

        int index = from_index(r);

        connection = &(connection_pool[index]);

        scratch_arena_data = connection->client.scratch_arena_data;
        scratch_arena_raw = scratch_arena_data->arena;
    }

    assert(connection != NULL);

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

    scratch_arena_data = connection_pool[index].client.scratch_arena_data;
    scratch_arena_raw = scratch_arena_data->arena;

    connection = &(connection_pool[index]);

    while (PQisBusy(connection->conn)) {
        int _conn_fd = PQsocket(connection->conn);

        printf("busy socket: %d\n", _conn_fd);

        if (!PQconsumeInput(connection->conn)) {
            fprintf(stderr, "PQconsumeInput failed: %s\n", PQerrorMessage(connection->conn));
        }
    }

    PGresult *res;
    while ((res = PQgetResult(connection->conn)) != NULL) {
        if (PQresultStatus(res) != PGRES_TUPLES_OK && PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Query failed: %s\n", PQerrorMessage(connection->conn));
            PQclear(res);
            break;
        }

        print_query_result(res);

        PQclear(res);
    }

    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *template = get_value("home", sizeof("home"), p_global_arena_data->html.component_dict);

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

    render(template_cpy, "table", 3, key_value_01, key_value_02, key_value_03);

    render(template_cpy, "rows", 2, empty, empty);
    render(template_cpy, "cells", 3, empty, empty, empty);
    render(template_cpy, "cells", 1, empty);

    render(template_cpy, "rows", 5, empty, empty, empty, empty, empty);
    render(template_cpy, "cells", 4, empty, empty, empty);
    render(template_cpy, "cells", 1, empty);
    render(template_cpy, "cells", 1, empty);
    render(template_cpy, "cells", 2, empty, empty, empty);
    render(template_cpy, "cells", 1, empty);

    render(template_cpy, "rows", 3, empty, empty, empty);
    render(template_cpy, "cells", 1, empty);
    render(template_cpy, "cells", 1, empty);
    render(template_cpy, "cells", 1, empty);

    /* TODO: add support for (0 times) -> render(template_cpy, "cells", 0); */

    scratch_arena_raw->current = (char *)scratch_arena_raw->current + strlen(template_cpy) + 1;

    char *response_html_minified = (char *)scratch_arena_raw->current;
    html_minify(response_html_minified, template_cpy, strlen(template_cpy));

    scratch_arena_raw->current = (char *)scratch_arena_raw->current + strlen(response_html_minified) + 1;

    size_t response_length = strlen(response_headers) + strlen(response_html_minified);

    char *response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, response_html_minified);
    response[response_length] = '\0';

    int resl = send(scratch_arena_data->client_socket, response, strlen(response), 0);
    if (resl == -1) {
        /** TODO: Write error to logs */
    }

    close(scratch_arena_data->client_socket);
    printf("Terminated - client-fd: %d\n", scratch_arena_data->client_socket);

    h_count++;
    printf("Handled requests: %d\n", h_count);

    uint8_t was_queued = connection->client.queued;

    /* release connection for others to use */
    memset(&(connection->client), 0, sizeof(Client));

    int conn_fd = PQsocket(connection->conn);

    event.events = EPOLLOUT | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_fd, &event);

    arena_free(scratch_arena_raw);

    if (was_queued) {
        longjmp(db_ctx, 1); /** Jump back */
    } else {
        longjmp(ctx, 1); /** Jump back */
    }
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void not_found(int client_socket) {
    char response[] = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
                      "<html><body><h1>404 Not Found</h1></body></html>";

    if (send(client_socket, response, strlen(response), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(client_socket);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
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

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
char hex_to_char(char c) {
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
 * TODO: ADD FUNCTION DOCUMENTATION
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
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void read_file(char **buffer, long *file_size, char *absolute_file_path) {
    FILE *file = fopen(absolute_file_path, "r");
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) != -1);
    *file_size = ftell(file);
    assert(*file_size != -1);
    rewind(file);

    *buffer = (char *)malloc(*file_size * sizeof(char));
    assert(*buffer != NULL);

    size_t read_size = fread(*buffer, sizeof(char), *file_size, file);
    assert(read_size == (size_t)*file_size);

    fclose(file);
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
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

                char *end = start;
                while (*end != '\n') {
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
 * TODO: ADD FUNCTION DOCUMENTATION
 */
char *get_value(const char key[], size_t key_length, CharsBlock block) {
    char *ptr = block.start_addr;
    while (ptr < block.end_addr) {
        if (strncmp(ptr, key, key_length) == 0) {
            ptr += strlen(ptr) + 1;
            return (ptr);
        }

        ptr += strlen(ptr) + 1; /* Advance past key */
        ptr += strlen(ptr) + 1; /* Advance past value */
    }

    return NULL;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
char *load_db_connection_string(const char *filepath) {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char *file_content = NULL;
    long file_size = 0;
    read_file(&file_content, &file_size, filepath);

    char *connection_string = (char *)arena_alloc(p_global_arena_raw, (size_t)file_size + 1);
    memcpy(connection_string, file_content, (size_t)file_size);
    connection_string[file_size] = '\0';

    p_global_arena_data->db_connection_string = connection_string;

    free(file_content);
    file_content = NULL;

    return connection_string;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
CharsBlock load_env_variables(const char *filepath) {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char *file_content = NULL;
    long file_size = 0;
    read_file(&file_content, &file_size, filepath);

    assert(file_size != 0);

    /** Envs will be stored in a dictionary */
    char *envs = (char *)p_global_arena_raw->current;
    p_global_arena_data->envs.start_addr = p_global_arena_raw->current;

    char *tmp_envs = envs;

    char *line = file_content;
    char *end = file_content + file_size;

    while (line < end) { /** Basic .env file parsing. */
        uint8_t processed_key = 0;
        uint8_t processed_value = 0;

        char *c = line;

        /** Skip empty lines */
        if (*c == '\n') {
            goto end_of_line;
        }

        /** Skip comment line */
        if (*c == '#') {
            while (*c != '\n') {
                if (c == end) {
                    goto end_of_line;
                }

                c++;
            }

            goto end_of_line;
        }

        /** Skip whitespace characters at the beginning of the line */
        while (isspace(*c)) {
            if (c == end) {
                goto end_of_line;
            }

            c++;
        }

        /** Start processing key */
        while (!(isspace(*c)) && *c != '=') {
            if (c == end) {
                /**
                 * If we've reached the end of the file while processing
                 * the key, such variable does not have an associated value.
                 */
                assert(0);
            }

            /** Copy key into memory buffer */
            *tmp_envs = *c;
            tmp_envs++;

            c++;
        }

        *tmp_envs = '\0';
        tmp_envs++;

        processed_key = 1;

        /** Skip whitespace characters after key */
        while (isspace(*c)) {
            if (c == end) {
                goto end_of_line;
            }

            c++;
        }

        /**
         * The first non-whitespace character we should find after
         * the key is the '=' after which comes the value.
         */
        if (*c != '=') {
            assert(0);
        } else {
            /** Skip '=' character */
            c++;
        }

        /** Skip whitespace characters after '=' */
        while (isspace(*c)) {
            if (c == end) {
                goto end_of_line;
            }

            c++;
        }

        /** From here we start processing value */
        uint8_t processing_value = 0;
        while (!(isspace(*c))) {
            if ((*c) != '\0') {
                processing_value = 1;
            }

            if (c == end) {
                /** Reached the end of the file while processing the value */
                if (processing_value) {
                    processed_value = 1;
                }

                goto end_of_line;
            }

            /** Copy value into memory buffer */
            *tmp_envs = *c;
            tmp_envs++;

            c++;
        }

        *tmp_envs = '\0';
        tmp_envs++;

        processed_value = 1;

        /** Skip all character after the value and proceed to next line */
        while (*c != '\n') {
            if (c == end) {
                goto end_of_line;
            }

            c++;
        }

    end_of_line:
        line = c + 1;

        if ((processed_key == 0) != (processed_value == 0)) {
            /**
             * Key and value must be processed together.
             * One should not be processed without the other.
             */
            assert(0);
        }

        processed_key = 0;
        processed_value = 0;
    }

    p_global_arena_data->envs.end_addr = tmp_envs;
    p_global_arena_raw->current = tmp_envs + 1;

    free(file_content);
    file_content = NULL;

    return p_global_arena_data->envs;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
CharsBlock load_public_files(const char *base_path) {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    /** Find the paths of all static files (in this case, all file stored in PUBLIC_FOLDER or subfolders) */
    char *public_files_paths = (char *)p_global_arena_raw->current;
    p_global_arena_data->public.paths.start_addr = public_files_paths;
    uint8_t public_files_count = 0;
    size_t all_paths_length = 0;
    locate_files(public_files_paths, base_path, NULL, 0, &public_files_count, &all_paths_length);
    p_global_arena_data->public.paths.end_addr = public_files_paths + all_paths_length;
    p_global_arena_raw->current = p_global_arena_data->public.paths.end_addr + 1;

    /** Load files into memory arena as key(file path) value(file content) dict */
    char *public_files = (char *)p_global_arena_raw->current;
    p_global_arena_data->public.file_dict.start_addr = public_files;
    char *tmp_public_files = public_files;
    char *tmp_public_files_paths = p_global_arena_data->public.paths.start_addr;
    char extension[] = ".html";
    while (tmp_public_files_paths < p_global_arena_data->public.paths.end_addr) {
        /** NOT interested in html files, they will be loaded differently */
        if (strncmp(tmp_public_files_paths + strlen(tmp_public_files_paths) - strlen(extension), extension, strlen(extension)) == 0) {
            tmp_public_files_paths += strlen(tmp_public_files_paths) + 1;
            continue;
        }

        char *file_content = NULL;
        long file_size = 0;
        read_file(&file_content, &file_size, tmp_public_files_paths);

        /** File path key */
        strncpy(tmp_public_files, tmp_public_files_paths, strlen(tmp_public_files_paths) + 1);
        tmp_public_files += strlen(tmp_public_files_paths) + 1;

        /** File content value */
        strncpy(tmp_public_files, file_content, file_size + 1);
        tmp_public_files += file_size + 1;

        free(file_content);
        file_content = NULL;

        tmp_public_files_paths += strlen(tmp_public_files_paths) + 1;
    }

    p_global_arena_data->public.file_dict.end_addr = tmp_public_files;
    p_global_arena_raw->current = p_global_arena_data->public.file_dict.end_addr + 1;

    return p_global_arena_data->public.file_dict;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
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
 * TODO: ADD FUNCTION DOCUMENTATION
 */
CharsBlock load_html_components(const char *base_path) {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    /** Find the paths of all html files */
    char *html_files_paths = (char *)p_global_arena_raw->current;
    p_global_arena_data->html.raw.paths.start_addr = html_files_paths;
    char extension[] = ".html";
    uint8_t html_files_count = 0;
    size_t all_paths_length = 0;
    locate_files(html_files_paths, base_path, extension, 0, &html_files_count, &all_paths_length);
    p_global_arena_data->html.raw.paths.end_addr = html_files_paths + all_paths_length;
    p_global_arena_raw->current = p_global_arena_data->html.raw.paths.end_addr + 1;

    /* A Component is an HTML snippet that may include references to other HTML snippets, i.e., it is composable */
    char *components = (char *)p_global_arena_raw->current;
    p_global_arena_data->html.raw.component_dict.start_addr = components;
    char *tmp_components = components;

    uint8_t components_count = 0;

    char *tmp_filepath = p_global_arena_data->html.raw.paths.start_addr;
    while (tmp_filepath < p_global_arena_data->html.raw.paths.end_addr) {
        char *file_content = NULL;
        long file_size = 0;
        read_file(&file_content, &file_size, tmp_filepath);

        /**
         * A .html file may contain multiple Components and they are
         * loaded into memory as key(component name) value(component html)
         */
        char *tmp_file_content = file_content;
        while ((tmp_file_content = strstr(tmp_file_content, COMPONENT_DEFINITION_OPENING_TAG__START)) != NULL) { /** Process Components inside .html file. */
            /** Start processing key (component name) */
            char *component_name_start = tmp_file_content + strlen(COMPONENT_DEFINITION_OPENING_TAG__START);
            char *component_name_end = NULL;

            uint8_t component_name_length = 0;

            if ((component_name_end = strchr(component_name_start, '\"')) != NULL) {
                component_name_length = component_name_end - component_name_start;
                strncpy(tmp_components, component_name_start, component_name_length);
                tmp_components[component_name_length] = '\0';
                tmp_components += component_name_length + 1;
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

            size_t minified_html_length = html_minify(tmp_components, html, html_length);

            tmp_components += minified_html_length;

            components_count++;
            tmp_file_content++;
        }

        free(file_content);
        file_content = NULL;

        tmp_filepath += strlen(tmp_filepath) + 1;
    }

    p_global_arena_data->html.raw.component_dict.end_addr = tmp_components;
    p_global_arena_raw->current = tmp_components + 1;

    p_global_arena_data->html.raw.count = components_count;

    return p_global_arena_data->html.raw.component_dict;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
CharsBlock resolve_html_components_imports() {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    uint8_t i;

    /* An HTML template is essentially a Component that has been compiled with all its imports. */
    char *html_templates = (char *)p_global_arena_raw->current;
    p_global_arena_data->html.component_dict.start_addr = html_templates;

    char *tmp_html_templates = html_templates;

    char *components = p_global_arena_data->html.raw.component_dict.start_addr;
    char *tmp_components = components;

    uint8_t components_count = p_global_arena_data->html.raw.count;

    for (i = 0; i < components_count; i++) { /** Compile Components. */
        uint8_t html_template_name_length = (uint8_t)strlen(tmp_components);
        strncpy(tmp_html_templates, tmp_components, html_template_name_length);
        tmp_html_templates[html_template_name_length] = '\0';

        tmp_html_templates += html_template_name_length + 1;

        tmp_components += strlen(tmp_components) + 1; /* Advance pointer to component markdown */

        size_t component_markdown_length = strlen(tmp_components);
        strncpy(tmp_html_templates, tmp_components, component_markdown_length);
        tmp_html_templates[component_markdown_length] = '\0';

        char *template_start = tmp_html_templates;

        char *component_import_opening_tag = tmp_html_templates;
        while ((component_import_opening_tag = strstr(component_import_opening_tag, COMPONENT_IMPORT_OPENING_TAG__START)) != NULL) { /** Resolve Component imports. */
            tmp_html_templates += (component_import_opening_tag - tmp_html_templates);

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

                            size_t len = strlen(tmp_html_templates + import_statement_length);
                            memmove(tmp_html_templates + component_markdown_length, tmp_html_templates + import_statement_length, len); /* ATTENTION! */
                            char *ptr = tmp_html_templates + component_markdown_length + len;
                            ptr[0] = '\0';
                            ptr++;
                            while (*ptr) {
                                size_t str_len = strlen(ptr);
                                memset(ptr, 0, str_len);
                                ptr += str_len + 1;
                            }

                            memcpy(tmp_html_templates, tmp_components_j, component_markdown_length);

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
                    tmp_html_templates = template_start;

                    break;
                }

                if (strncmp(tmp_import_name, COMPONENT_IMPORT_OPENING_TAG__END, strlen(COMPONENT_IMPORT_OPENING_TAG__END)) == 0) { /** Import contain "slots" */
                    imported_name_length = tmp_import_name - import_name_start;

                    char *tmp_components_j = components;

                    uint8_t j;
                    for (j = 0; j < components_count; j++) {
                        if (strncmp(tmp_components_j, import_name_start, imported_name_length) == 0) {
                            tmp_components_j += strlen(tmp_components_j) + 1; /* Advance pointer to component markdown */

                            resolve_slots(tmp_components_j, component_import_opening_tag, &tmp_html_templates);

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
        tmp_html_templates += strlen(tmp_html_templates) + 1;
    }

    p_global_arena_raw->current = tmp_html_templates;
    p_global_arena_data->html.component_dict.end_addr = (char *)p_global_arena_raw->current - 1;

    return p_global_arena_data->html.component_dict;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
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

    assert(listen(server_fd, MAX_CONNECTIONS) != -1);

    Socket *server_socket = arena_alloc(p_global_arena_raw, sizeof(Socket));
    server_socket->fd = server_fd;
    server_socket->type = SERVER_SOCKET;

    p_global_arena_data->socket = server_socket;

    return p_global_arena_data->socket;
}

/** BUG: Sometimes it does not create all the needed connections on application start up */
/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void create_connection_pool(const char *conn_info) {
    uint8_t i;
    for (i = 0; i < CONNECTION_POOL_SIZE; i++) {
        connection_pool[i].conn = PQconnectStart(conn_info);
        if (PQstatus(connection_pool[i].conn) != CONNECTION_BAD) {
            PQsetnonblocking(connection_pool[i].conn, 1);

            connection_pool[i].type = DB_SOCKET;
            connection_pool[i].index = i;

            int fd = PQsocket(connection_pool[i].conn);

            event.events = EPOLLOUT | EPOLLET;
            event.data.ptr = &(connection_pool[i]);
            assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) != -1);
        } else {
            fprintf(stderr, "Connection failed: %s\n", PQerrorMessage(connection_pool[i].conn));
        }
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
                    event.events = EPOLLIN | EPOLLET;
                    event.data.ptr = connection;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
                } else if (poll_status == PGRES_POLLING_WRITING) {
                    event.events = EPOLLOUT | EPOLLET;
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
 * TODO: ADD FUNCTION DOCUMENTATION
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
 * TODO: ADD FUNCTION DOCUMENTATION
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
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void arena_reset(Arena *arena, size_t arena_header_size) {
    uint8_t *start = (uint8_t *)arena->start + arena_header_size;

    size_t set_bytes = (uint8_t *)arena->current - start;
    memset(start, 0, set_bytes);

    arena->current = start;
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
 */
void arena_free(Arena *arena) {
    if (munmap(arena->start, arena->size) == -1) {
        assert(0);
    }
}

/**
 * TODO: ADD FUNCTION DOCUMENTATION
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