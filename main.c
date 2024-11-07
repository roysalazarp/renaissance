#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <signal.h>
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

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

#define MAX_PATH_LENGTH 200
#define MAX_FILES 20
#define MAX_CONNECTIONS 100    /** ?? */
#define CONNECTION_POOL_SIZE 5 /** ?? */

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

typedef enum { SERVER_SOCKET, CLIENT_SOCKET, DB_SOCKET } FDType;

typedef struct {
    int fd;
    FDType type;
} SocketInfo;

typedef struct {
    size_t size;
    void *start;
    void *current;
} Arena;

typedef struct {
    char *start_addr;
    size_t length;
} RequestValue;

typedef struct {
    uint8_t *start_addr;
    uint8_t *end_addr;
} MemBlock;

typedef struct {
    char *start_addr;
    char *end_addr;
} CharsBlock;

typedef struct {
    Arena *arena;
    CharsBlock env;
    CharsBlock public_files_paths;
    CharsBlock statics;
    CharsBlock components;
    uint8_t components_count;
    CharsBlock html_templates;
    MemBlock connection_msg;
    SocketInfo *socket;
} GlobalArenaDataLookup;

typedef struct {
    Arena *arena;
    int client_socket;
    CharsBlock request;
    void *local;
} ScratchArenaDataLookup;

typedef struct {
    int fd;
    Arena *scratch_arena_raw;
    ScratchArenaDataLookup *scratch_arena_data;
    jmp_buf jmp_buf;
} Client;

typedef struct {
    SocketInfo socket;
    uint8_t index;
    Client client;
    uint8_t alive;
} Connection;

typedef struct {
    MemBlock users_id_query;
    MemBlock users_id_query_response;
    CharsBlock http_response;
} HomeGetContext;

void sigint_handler(int signo);
void router(Arena *scratch_arena_raw);
void sign_up_create_user_post(Arena *scratch_arena_raw);
void sign_up_get(Arena *scratch_arena_raw);
void styles_get(Arena *scratch_arena_raw);
void manifest_get(Arena *scratch_arena_raw);
void home_get(Arena *scratch_arena_raw);
void not_found(int client_socket);
void locate_files(char *buffer, const char *base_path, const char *extension, uint8_t level, uint8_t *total_html_files, size_t *all_paths_length);
size_t url_decode_utf8(char **string, size_t length);
char hex_to_char(char c);
Arena *arena_init(size_t size);
void *arena_alloc(Arena *arena, size_t size);
void arena_free(Arena *arena);
void arena_reset(Arena *arena, size_t arena_header_size);
void read_file(char **buffer, long *file_size, char *absolute_file_path);
void resolve_slots(char *component_markdown, char *import_statement, char **templates);
char *get_value(const char key[], CharsBlock block);
RequestValue find_http_request_value(const char key[], char *request);
uint16_t string_to_uint16(const char *str);
void load_env_variables();
void load_static();
void load_html_components();
void resolve_html_components_imports();
SocketInfo *create_server_socket(uint16_t port);
void create_connection_pool(int server_fd);
void get_public_files_path();
CharsBlock parse_body_value(const char key_name[], char *request_body);
char *find_body(CharsBlock request);

volatile sig_atomic_t keep_running = 1;

Arena *_p_global_arena_raw;
GlobalArenaDataLookup *_p_global_arena_data;

int epoll_fd;
int nfds;
struct epoll_event events[MAX_EVENTS];
struct epoll_event event;

#define to_index(i) (i + 1)
#define from_index(i) (i - 1)

Connection connection_pool[CONNECTION_POOL_SIZE];

jmp_buf ctx;

int h_count;

int main() {
    int retval = 0;

    uint8_t i;

    _p_global_arena_raw = arena_init(PAGE_SIZE * 20);

    /**
     * Store the pointer in a stack variable, as the
     * stack is more likely to remain in the L1 cache.
     */
    Arena *p_global_arena_raw = _p_global_arena_raw;

    /** For convenient access to all data stored in the GlobalArenaDataLookup arena. */
    _p_global_arena_data = (GlobalArenaDataLookup *)arena_alloc(p_global_arena_raw, sizeof(GlobalArenaDataLookup));
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    p_global_arena_data->arena = p_global_arena_raw;

    load_env_variables();
    get_public_files_path();
    load_static();
    load_html_components();
    resolve_html_components_imports();

    /**
     * Registers a signal handler for SIGINT (to terminate the process)
     * to exit the program gracefully for Valgrind to show the program report.
     */
    assert(signal(SIGINT, sigint_handler) != SIG_ERR);

    epoll_fd = epoll_create1(0);
    assert(epoll_fd != -1);

    uint16_t port = 8080;
    SocketInfo *server_socket = create_server_socket(port);
    int server_fd = server_socket->fd;

    event.events = EPOLLIN;
    event.data.ptr = server_socket;
    assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) != -1);

    printf("Server listening on port: %d...\n", port);

    create_connection_pool(server_fd);

    struct sockaddr_in client_addr; /** Why is this needed ?? */
    socklen_t client_addr_len = sizeof(client_addr);

    while (1) {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, BLOCK_EXECUTION);
        assert(nfds != -1);

        for (i = 0; i < nfds; i++) {
            SocketInfo *socket_info = (SocketInfo *)events[i].data.ptr;

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
                        SocketInfo *client_socket_info = (SocketInfo *)arena_alloc(scratch_arena_raw, sizeof(SocketInfo));
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
                        Connection *db_socket = (Connection *)socket_info;

                        /** The connection should belong to a client fd (aka request) */
                        assert(db_socket->client.fd != 0);

                        /** Go back to where you attempted to read the result of a
                         * query but jumped out since we are not supposed to wait
                         * for response to be ready. Pass index to restore request
                         * state through connection pool */
                        longjmp(db_socket->client.jmp_buf, to_index(db_socket->index));
                    } else if (events[i].events & EPOLLOUT) { /** DB socket (aka connection) is ready for write */
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

    return retval;
}

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

void router(Arena *scratch_arena_raw) {
    int i;

    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(SocketInfo)));

    int client_socket = scratch_arena_data->client_socket;

    printf("Handling - client-fd: %d\n", client_socket);

    char *request = (char *)scratch_arena_raw->current;
    scratch_arena_data->request.start_addr = scratch_arena_raw->current;

    char *tmp_request = request;

    ssize_t read_stream = 0;
    ssize_t buffer_size = KB(2);

    int8_t does_http_request_contain_body = -1; /* -1 means we haven't checked yet */
    RequestValue method;

    int8_t is_multipart_form_data = -1; /* -1 means we haven't checked yet */
    RequestValue content_type;

    while (1) {
        char *advanced_request_ptr = tmp_request + read_stream;

        ssize_t incomming_stream_size = recv(client_socket, advanced_request_ptr, buffer_size - read_stream, 0);
        if (incomming_stream_size == -1) {
            printf("Error: %s\n", strerror(errno));

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (read_stream > 0) {
                    break;
                }

                longjmp(ctx, 1); /* ?? */
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

    RequestValue url = find_http_request_value("URL", scratch_arena_data->request.start_addr);

    if (strlen(scratch_arena_data->request.start_addr) == 0) {
        printf("Request is empty\n");

        close(client_socket);
        printf("Terminated - client-fd: %d\n", client_socket);
    } else if (strncmp(url.start_addr, "/styles.css", strlen("/styles.css")) == 0 && strncmp(method.start_addr, "GET", method.length) == 0) {
        styles_get(scratch_arena_raw);
    } else if (strncmp(url.start_addr, "/manifest.json", strlen("/manifest.json")) == 0 && strncmp(method.start_addr, "GET", method.length) == 0) {
        manifest_get(scratch_arena_raw);
    } else if (strncmp(url.start_addr, "/ ", strlen("/ ")) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            home_get(scratch_arena_raw);
        }
    } else if (strncmp(url.start_addr, "/sign-up ", strlen("/sign-up ")) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            sign_up_get(scratch_arena_raw);
        }
    } else if (strncmp(url.start_addr, "/sign-up/create-user ", strlen("/sign-up/create-user ")) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            sign_up_create_user_post(scratch_arena_raw);
        }
    } else {
        not_found(client_socket);
    }
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

typedef struct __attribute__((packed)) {
    /* Parse message */
    char parse_msg_type;
    uint32_t parse_msg_length;
    char parse_unnamed_statement;
    char command[53]; /* "SELECT * FROM app.countries WHERE id = $1 OR id = $2" */
    uint16_t nParams_for_paramTypes;
    uint32_t paramType_01;
    uint32_t paramType_02;

    /* Bind message */
    char bind_msg_type;
    uint32_t bind_msg_length;
    char bind_unnamed_portal;
    char bind_unnamed_statement;

    uint16_t nParams_for_paramFormats;
    uint16_t paramFormat_01;
    uint16_t paramFormat_02;

    uint16_t nParams_for_paramValues;
    uint32_t paramValuesSize_01;
    int paramValues_01;
    uint32_t paramValuesSize_02;
    int paramValues_02;

    uint16_t num_1;
    uint16_t result_format;

    /* Describe Portal message */
    char describe_portal_msg_type;
    uint32_t describe_portal_msg_length;
    char P;
    char describe_portal_empty_string;

    /* Execute message */
    char execute_msg_type;
    uint32_t execute_msg_length;
    char execute_empty_string;
    uint32_t num_0;

    /* Sync message */
    char sync_msg_type;
    uint32_t sync_msg_length;
} SelectTwoCountriesQuery;

SelectTwoCountriesQuery select_two_countries_query() {
    SelectTwoCountriesQuery query = {0};

    /* Parse message */
    query.parse_msg_type = 'P';
    /* clang-format off */
    query.parse_msg_length = htonl(sizeof(query.parse_msg_length) 
                                 + sizeof(query.parse_unnamed_statement) 
                                 + 53 
                                 + sizeof(query.nParams_for_paramTypes) 
                                 + sizeof(query.paramType_01) 
                                 + sizeof(query.paramType_02));
    /* clang-format on */
    query.parse_unnamed_statement = (char)0;
    memcpy(query.command, "SELECT * FROM app.countries WHERE id = $1 OR id = $2", 53);
    query.nParams_for_paramTypes = htons((uint16_t)2);
    query.paramType_01 = htonl((uint32_t)23);
    query.paramType_02 = htonl((uint32_t)23);

    /* Bind message */
    query.bind_msg_type = 'B';
    /* clang-format off */
    query.bind_msg_length = htonl(sizeof(query.bind_msg_length) 
                                + sizeof(query.bind_unnamed_portal) 
                                + sizeof(query.bind_unnamed_statement) 
                                + sizeof(query.nParams_for_paramFormats) 
                                + sizeof(query.paramFormat_01) 
                                + sizeof(query.paramFormat_02) 
                                + sizeof(query.nParams_for_paramValues) 
                                + sizeof(query.paramValuesSize_01) 
                                + sizeof(query.paramValues_01) 
                                + sizeof(query.paramValuesSize_02) 
                                + sizeof(query.paramValues_02) 
                                + sizeof(query.num_1) 
                                + sizeof(query.result_format));
    /* clang-format on */
    query.bind_unnamed_portal = (char)0;
    query.bind_unnamed_statement = (char)0;

    query.nParams_for_paramFormats = htons((uint16_t)2);
    query.paramFormat_01 = htons((uint16_t)1);
    query.paramFormat_02 = htons((uint16_t)1);

    query.nParams_for_paramValues = htons((uint16_t)2);
    query.paramValuesSize_01 = htonl((uint32_t)4);
    query.paramValues_01 = htonl((int)3);
    query.paramValuesSize_02 = htonl((uint32_t)4);
    query.paramValues_02 = htonl((int)23);

    query.num_1 = htons((uint16_t)1);
    query.result_format = htons((uint16_t)0);

    /* Describe Portal message */
    query.describe_portal_msg_type = 'D';
    /* clang-format off */
    query.describe_portal_msg_length = htonl(sizeof(query.describe_portal_msg_length) 
                                           + sizeof(query.P) 
                                           + sizeof(query.describe_portal_empty_string));
    /* clang-format on */
    query.P = 'P';
    query.describe_portal_empty_string = (char)0;

    /* Execute message */
    query.execute_msg_type = 'E';
    /* clang-format off */
    query.execute_msg_length = htonl(sizeof(uint32_t) 
                                   + sizeof(query.execute_empty_string) 
                                   + sizeof(uint32_t));
    /* clang-format on */
    query.execute_empty_string = (char)0;
    query.num_0 = htonl((uint32_t)0);

    /* Sync message */
    query.sync_msg_type = 'S';
    query.sync_msg_length = htonl(sizeof(uint32_t));

    return query;
}

void sign_up_create_user_post(Arena *scratch_arena_raw) {
    /** Process signup */

    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(SocketInfo)));

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

void sign_up_get(Arena *scratch_arena_raw) {
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(SocketInfo)));

    int client_socket = scratch_arena_data->client_socket;

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *template = get_value("sign-up", p_global_arena_data->html_templates);

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

void styles_get(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(SocketInfo)));

    int client_socket = scratch_arena_data->client_socket;

    char *tmp_statics = _p_global_arena_data->statics.start_addr;
    char *end = _p_global_arena_data->statics.end_addr;

    char *css;

    char key[] = "./public/styles.css";
    while (tmp_statics < end) {
        if (strncmp(key, tmp_statics, strlen(key)) == 0) {
            tmp_statics += strlen(tmp_statics) + 1;

            css = tmp_statics;
            break;
        }

        tmp_statics += strlen(tmp_statics) + 1;
        tmp_statics += strlen(tmp_statics) + 1;
    }

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n";
    size_t response_length = strlen(response_headers) + strlen(css);

    char *response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, css);
    response[response_length] = '\0';

    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);
    printf("terminated - client-fd: %d\n", client_socket);

    arena_reset(scratch_arena_raw, sizeof(Arena) + sizeof(ScratchArenaDataLookup));
}

void manifest_get(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(SocketInfo)));

    int client_socket = scratch_arena_data->client_socket;

    char *tmp_statics = _p_global_arena_data->statics.start_addr;
    char *end = _p_global_arena_data->statics.end_addr;

    char *manifest;

    char key[] = "./public/manifest.json";
    while (tmp_statics < end) {
        if (strncmp(key, tmp_statics, strlen(key)) == 0) {
            tmp_statics += strlen(tmp_statics) + 1;

            manifest = tmp_statics;
            break;
        }

        tmp_statics += strlen(tmp_statics) + 1;
        tmp_statics += strlen(tmp_statics) + 1;
    }

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n\r\n";
    size_t response_length = strlen(response_headers) + strlen(manifest);

    char *response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, manifest);
    response[response_length] = '\0';

    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);
    printf("terminated - client-fd: %d\n", client_socket);

    arena_free(scratch_arena_raw);
}

void home_get(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(SocketInfo)));
    scratch_arena_data->local = (HomeGetContext *)arena_alloc(scratch_arena_raw, sizeof(HomeGetContext));

    HomeGetContext *local = scratch_arena_data->local;

    Connection *conn;

    int i;
    for (i = 0; i < CONNECTION_POOL_SIZE; i++) {
        if (connection_pool[i].alive && connection_pool[i].client.fd == 0) {

            connection_pool[i].client.fd = scratch_arena_data->client_socket;
            connection_pool[i].client.scratch_arena_raw = scratch_arena_raw;
            connection_pool[i].client.scratch_arena_data = scratch_arena_data;

            conn = &(connection_pool[i]);

            break;
        }
    }

    assert(conn != NULL);

    SelectTwoCountriesQuery my_query = select_two_countries_query();

    char message_type = 'Q';
    char users_id_query_local[] = "SELECT id FROM app.users";
    int32_t message_length = htonl((int32_t)(sizeof(users_id_query_local)) + (int32_t)(sizeof(int32_t)));
    size_t users_id_query_length = sizeof(char) + sizeof(int32_t) + (strlen(users_id_query_local) + 1);

    uint8_t *users_id_query = arena_alloc(scratch_arena_raw, users_id_query_length);
    memcpy(users_id_query, &message_type, sizeof(char));
    memcpy(users_id_query + sizeof(char), &message_length, sizeof(int32_t));
    memcpy(users_id_query + sizeof(char) + sizeof(int32_t), &users_id_query_local, (strlen(users_id_query_local) + 1));

    local->users_id_query.start_addr = users_id_query;
    local->users_id_query.end_addr = users_id_query + users_id_query_length;

    size_t msg_length = local->users_id_query.end_addr - local->users_id_query.start_addr;
    /*
    ssize_t bytes_sent = send(conn->socket.fd, local->users_id_query.start_addr, msg_length, 0);
    */
    ssize_t bytes_sent = send(conn->socket.fd, &my_query, sizeof(my_query), 0);
    if (bytes_sent == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /** ? */
            printf("here!?\n");
        }
    }

retry:
    local->users_id_query_response.start_addr = (uint8_t *)scratch_arena_raw->current;
    ssize_t read_stream = 0;
    while (1) {
        uint8_t *ptr = local->users_id_query_response.start_addr + read_stream;

        ssize_t incomming_stream_size = recv(conn->socket.fd, ptr, KB(1) - read_stream, 0);
        if (incomming_stream_size == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                event.events = EPOLLIN | EPOLLET;
                event.data.ptr = &(conn->socket);
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->socket.fd, &event);

                int r = setjmp(conn->client.jmp_buf);
                if (r == 0) {
                    longjmp(ctx, 1);
                }

                int index = from_index(r);

                scratch_arena_data = connection_pool[index].client.scratch_arena_data;
                scratch_arena_raw = scratch_arena_data->arena;

                local = scratch_arena_data->local;
                conn = &(connection_pool[index]);

                goto retry;
            }
        }

        if (incomming_stream_size == 0) {
            printf("Postgres server closed connection\n");

            break;
        }

        read_stream += incomming_stream_size;

        if (incomming_stream_size <= 0) {
            break;
        }

        local->users_id_query_response.end_addr = local->users_id_query_response.start_addr + read_stream;

        ssize_t j;
        for (j = 0; j < read_stream; j++) {
            printf("%c", (unsigned char)local->users_id_query_response.start_addr[j]);
            if (j == read_stream - 1) {
                printf("\n");
            }
        }

        break;
    }

    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *template = get_value("home", p_global_arena_data->html_templates);

    size_t response_length = strlen(response_headers) + strlen(template);

    char *response = (char *)arena_alloc(scratch_arena_raw, response_length + 1);

    sprintf(response, "%s%s", response_headers, template);
    response[response_length] = '\0';

    int resl = send(scratch_arena_data->client_socket, response, strlen(response), 0);
    if (resl == -1) {
        /** TODO: Write error to logs */
    }

    close(scratch_arena_data->client_socket);
    printf("Terminated - client-fd: %d\n", scratch_arena_data->client_socket);

    h_count++;
    printf("Handled requests: %d\n", h_count);

    /* release connection for others to use */
    memset(&(conn->client), 0, sizeof(Client));

    event.events = EPOLLOUT | EPOLLET;
    event.data.ptr = &(conn->socket);
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->socket.fd, &event);

    arena_free(scratch_arena_raw);

    longjmp(ctx, 1); /** Jump back */
}

void not_found(int client_socket) {
    char response[] = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
                      "<html><body><h1>404 Not Found</h1></body></html>";

    if (send(client_socket, response, strlen(response), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(client_socket);
}

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
 * Recursively searches for .html files in a directory and its subdirectories, storing their full
 * paths in the provided buffer.
 *
 * @buffer:            A buffer to store the full paths of located .html files.
 * @base_path:         The directory path where the search begins.
 * @level:             The current recursion depth (used for tracking subdirectory levels).
 * @total_html_files:  A pointer to a counter that tracks the total number of .html files found.
 * @all_paths_length:  A pointer to track the total length of all file paths combined (including null terminators).
 */
void locate_files(char *buffer, const char *base_path, const char *extension, uint8_t level, uint8_t *total_files, size_t *all_paths_length) {
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
                locate_files(buffer, path, extension, level + 1, total_files, all_paths_length);
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
}

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

RequestValue find_http_request_value(const char key[], char *request) {
    RequestValue value = {0};

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

char *get_value(const char key[], CharsBlock block) {
    char *ptr = block.start_addr;
    while (ptr < block.end_addr) {
        if (strncmp(ptr, key, strlen(key)) == 0) {
            ptr += strlen(ptr) + 1;
            return (ptr);
        }

        ptr += strlen(ptr) + 1; /* Advance past the key */
        ptr += strlen(ptr) + 1; /* Advance past the value */
    }

    assert(0);
}

void sigint_handler(int signo) {
    if (signo == SIGINT) {
        printf("\nReceived SIGINT, exiting program...\n");
        keep_running = 0;
    }
}

void load_env_variables() {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char *env_file_content = NULL;
    long file_size = 0;
    read_file(&env_file_content, &file_size, "./.env");

    assert(file_size != 0);

    char *env_vars = (char *)p_global_arena_raw->current;
    p_global_arena_data->env.start_addr = p_global_arena_raw->current;
    char *tmp_env_vars = env_vars;

    char *env_file_line = env_file_content;
    char *end_env_file = env_file_content + file_size;

    while (env_file_line < end_env_file) { /** Parse basic .env file format. */
        uint8_t env_var_name_processed = 0;
        uint8_t env_var_value_processed = 0;

        char *c = env_file_line;
        if (*c == '\n') {
            goto end_of_line;
        }

        if (*c == '#') {
            while (*c != '\n') {
                if (c == end_env_file) {
                    goto end_of_line;
                }

                c++;
            }

            goto end_of_line;
        }

        while (isspace(*c)) {
            if (c == end_env_file) {
                goto end_of_line;
            }

            c++;
        }

        /** Processing of environment variable name begins. */

        while (!(isspace(*c)) && *c != '=') {
            if (c == end_env_file) {
                /**
                 * If we've reached the end while processing an env variable
                 * name, such variable does not have an associated value.
                 */
                assert(0);
            }

            *tmp_env_vars = *c;
            tmp_env_vars++;

            c++;
        }

        *tmp_env_vars = '\0';
        tmp_env_vars++;

        env_var_name_processed = 1;

        while (isspace(*c)) {
            if (c == end_env_file) {
                goto end_of_line;
            }

            c++;
        }

        if (*c != '=') {
            assert(0);
        } else {
            c++;
        }

        while (isspace(*c)) {
            if (c == end_env_file) {
                goto end_of_line;
            }

            c++;
        }

        /** Processing of environment variable associated value begins. */

        uint8_t processing_value = 0;
        while (!(isspace(*c))) {
            if ((*c) != '\0') {
                processing_value = 1;
            }

            if (c == end_env_file) {
                if (processing_value) {
                    env_var_value_processed = 1;
                }

                goto end_of_line;
            }

            *tmp_env_vars = *c;
            tmp_env_vars++;

            c++;
        }

        *tmp_env_vars = '\0';
        tmp_env_vars++;

        env_var_value_processed = 1;

        while (*c != '\n') {
            if (c == end_env_file) {
                goto end_of_line;
            }

            c++;
        }

    end_of_line:
        env_file_line = c + 1;

        if ((env_var_name_processed == 0) != (env_var_value_processed == 0)) {
            /**
             * Environment variable name and value must be processed together.
             * One should not be processed without the other.
             */
            assert(0);
        }

        env_var_name_processed = 0;
        env_var_value_processed = 0;
    }

    p_global_arena_raw->current = tmp_env_vars + 1;
    p_global_arena_data->env.end_addr = (char *)p_global_arena_raw->current - 1;
}

void get_public_files_path() {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char *public_files_paths = (char *)p_global_arena_raw->current;
    p_global_arena_data->public_files_paths.start_addr = p_global_arena_raw->current;
    char *base_path = get_value("PUBLIC_FOLDER", p_global_arena_data->env);
    uint8_t public_files_count = 0;
    size_t all_paths_length = 0;
    locate_files(public_files_paths, base_path, NULL, 0, &public_files_count, &all_paths_length);

    p_global_arena_raw->current = (char *)p_global_arena_raw->current + all_paths_length;
    p_global_arena_data->public_files_paths.end_addr = (char *)p_global_arena_raw->current - 1;
}

void load_static() {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    char *statics = (char *)p_global_arena_raw->current;
    p_global_arena_data->statics.start_addr = p_global_arena_raw->current;
    char *tmp_statics = statics;

    char *tmp_filepath = p_global_arena_data->public_files_paths.start_addr;
    char *end = p_global_arena_data->public_files_paths.end_addr;
    char extension[] = ".html";

    while (tmp_filepath < end) {
        if (strncmp(tmp_filepath + strlen(tmp_filepath) - strlen(extension), extension, strlen(extension)) == 0) {
            /** NOT interested in '.html' files */

            tmp_filepath += strlen(tmp_filepath) + 1;
            continue;
        }

        char *file_content = NULL;
        long file_size = 0;
        read_file(&file_content, &file_size, tmp_filepath);

        /** Static file key */
        strncpy(tmp_statics, tmp_filepath, strlen(tmp_filepath) + 1);
        tmp_statics += strlen(tmp_filepath) + 1;

        /** Static file content */
        strncpy(tmp_statics, file_content, file_size + 1);
        tmp_statics += file_size + 1;

        free(file_content);
        file_content = NULL;

        tmp_filepath += strlen(tmp_filepath) + 1;
    }

    p_global_arena_raw->current = tmp_statics;
    p_global_arena_data->statics.end_addr = (char *)p_global_arena_raw->current - 1;
}

void load_html_components() {
    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    /* A Component is an HTML snippet that may include references to other HTML snippets, i.e., it is composable */
    char *components = (char *)p_global_arena_raw->current;
    p_global_arena_data->components.start_addr = p_global_arena_raw->current;
    char *tmp_components = components;

    uint8_t components_count = 0;

    char *tmp_filepath = p_global_arena_data->public_files_paths.start_addr;
    char *end = p_global_arena_data->public_files_paths.end_addr;
    char extension[] = ".html";

    while (tmp_filepath < end) {
        if (strncmp(tmp_filepath + strlen(tmp_filepath) - strlen(extension), extension, strlen(extension)) != 0) {
            /** Only interested in '.html' files */

            tmp_filepath += strlen(tmp_filepath) + 1;
            continue;
        }

        char *file_content = NULL;
        long file_size = 0;
        read_file(&file_content, &file_size, tmp_filepath); /** A .html file may contain multiple Components. */

        char *tmp_file_content = file_content;
        while ((tmp_file_content = strstr(tmp_file_content, COMPONENT_DEFINITION_OPENING_TAG__START)) != NULL) { /** Process Components inside .html file. */
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

            char *comp = tmp_components; /** TODO: Make this variable name more descriptive */
            char *tmp_component_markdown = tmp_file_content + strlen(COMPONENT_DEFINITION_OPENING_TAG__START) + (size_t)component_name_length + strlen(COMPONENT_DEFINITION_OPENING_TAG__END);

            uint8_t skip_whitespace = 0;
            while (*tmp_component_markdown) { /** Copy component markdown from file to buffer, removing unnecessary spaces. */
                if (strncmp(tmp_component_markdown, COMPONENT_DEFINITION_CLOSING_TAG, strlen(COMPONENT_DEFINITION_CLOSING_TAG)) == 0) {
                    break;
                }

                if (strlen(comp) == 0 && isspace(*tmp_component_markdown)) {
                    skip_whitespace = 1;
                    tmp_component_markdown++;
                    continue;
                }

                if (*tmp_component_markdown == '>') {
                    char *temp = tmp_component_markdown - 1;
                    if (isspace(*temp) && !skip_whitespace) {
                        uint8_t i = 0;
                        while (*temp) {
                            if (!isspace(*temp)) {
                                skip_whitespace = 1;
                                tmp_components -= i - 1;
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

                if (*tmp_component_markdown == '<') {
                    char *temp = tmp_component_markdown - 1;
                    if (isspace(*temp) && /* strlen(tmp_components) > 0 && */ !skip_whitespace) {
                        uint8_t i = 0;
                        while (*temp) {
                            if (!isspace(*temp)) {
                                skip_whitespace = 1;
                                tmp_components -= i - 1;
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

                if (!skip_whitespace && *tmp_component_markdown == '\n') {
                    tmp_component_markdown++;
                    continue;
                }

                if (skip_whitespace && isspace(*tmp_component_markdown)) {
                    tmp_component_markdown++;
                    continue;
                }

                if (skip_whitespace && !isspace(*tmp_component_markdown)) {
                    skip_whitespace = 0;
                    goto copy_char;
                }

            copy_char:
                *tmp_components = *tmp_component_markdown;
                tmp_components++;

                tmp_component_markdown++;
            }

            tmp_components[0] = '\0';
            tmp_components++;

            components_count++;
            tmp_file_content++;
        }

        free(file_content);
        file_content = NULL;

        tmp_filepath += strlen(tmp_filepath) + 1;
    }

    p_global_arena_raw->current = tmp_components;
    p_global_arena_data->components.end_addr = (char *)p_global_arena_raw->current - 1;

    p_global_arena_data->components_count = components_count;
}

void resolve_html_components_imports() {
    uint8_t i;

    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    /* An HTML template is essentially a Component that has been compiled with all its imports. */
    char *html_templates = (char *)p_global_arena_raw->current;
    p_global_arena_data->html_templates.start_addr = p_global_arena_raw->current;

    char *tmp_html_templates = html_templates;

    char *components = p_global_arena_data->components.start_addr;
    char *tmp_components = components;

    uint8_t components_count = p_global_arena_data->components_count;

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

                        tmp_components_j += strlen(tmp_components_j) + 1; /* Advance past the component name */
                        tmp_components_j += strlen(tmp_components_j) + 1; /* Advance past the component markdown */

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
    p_global_arena_data->html_templates.end_addr = (char *)p_global_arena_raw->current - 1;
}

SocketInfo *create_server_socket(uint16_t port) {
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

    SocketInfo *server_socket = arena_alloc(p_global_arena_raw, sizeof(SocketInfo));
    server_socket->fd = server_fd;
    server_socket->type = SERVER_SOCKET;

    p_global_arena_data->socket = server_socket;

    return p_global_arena_data->socket;
}

void create_connection_pool(int server_fd) {
    uint8_t i;

    Arena *p_global_arena_raw = _p_global_arena_raw;
    GlobalArenaDataLookup *p_global_arena_data = _p_global_arena_data;

    for (i = 0; i < CONNECTION_POOL_SIZE; i++) {
        int db_fd = socket(AF_INET, SOCK_STREAM, 0);
        assert(db_fd != -1);

        int db_fd_flags = fcntl(server_fd, F_GETFL, 0);
        assert(fcntl(db_fd, F_SETFL, db_fd_flags | O_NONBLOCK) != -1);

        int db_fd_optname = 1;
        assert(setsockopt(db_fd, SOL_SOCKET, SO_REUSEADDR, &db_fd_optname, sizeof(int)) != -1);

        struct sockaddr_in db_addr;
        db_addr.sin_family = AF_INET;
        db_addr.sin_port = htons(string_to_uint16(get_value("DB_PORT", p_global_arena_data->env)));

        memset(&db_addr.sin_zero, 0, sizeof(db_addr.sin_zero));
        assert(inet_pton(AF_INET, get_value("DB_HOST", p_global_arena_data->env), &db_addr.sin_addr) > 0);

        if (connect(db_fd, (struct sockaddr *)&db_addr, sizeof(db_addr)) < 0) {
            assert(errno == EINPROGRESS);
        }

        connection_pool[i].socket.fd = db_fd;
        connection_pool[i].socket.type = DB_SOCKET;
        connection_pool[i].index = i;

        event.events = EPOLLOUT | EPOLLET;
        event.data.ptr = &(connection_pool[i]);
        assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection_pool[i].socket.fd, &event) != -1);
    }

    uint8_t *connection_msg = (uint8_t *)p_global_arena_raw->current;
    p_global_arena_data->connection_msg.start_addr = p_global_arena_raw->current;
    uint8_t *tmp_connection_msg = connection_msg;

    /** Leave space at the very beginning for msg_length */
    tmp_connection_msg += sizeof(u_int32_t);

    u_int32_t protocol_version = htonl(0x00030000); /** version 3.0 */
    memcpy(tmp_connection_msg, &protocol_version, sizeof(protocol_version));
    tmp_connection_msg += sizeof(protocol_version);

    memcpy(tmp_connection_msg, "user", sizeof("user"));
    tmp_connection_msg += sizeof("user");

    char *user = get_value("DB_USER", p_global_arena_data->env);
    memcpy(tmp_connection_msg, user, strlen(user));
    tmp_connection_msg += strlen(user);
    *tmp_connection_msg = '\0';
    tmp_connection_msg++;

    memcpy(tmp_connection_msg, "database", sizeof("database"));
    tmp_connection_msg += sizeof("database");

    char *database = get_value("DB_NAME", p_global_arena_data->env);
    memcpy(tmp_connection_msg, database, strlen(database));
    tmp_connection_msg += strlen(database);
    *tmp_connection_msg = '\0';
    tmp_connection_msg++;

    *tmp_connection_msg = '\0';
    tmp_connection_msg++;

    size_t connection_msg_size = tmp_connection_msg - connection_msg;
    u_int32_t msg_length = htonl((u_int32_t)connection_msg_size);
    memcpy(connection_msg, &msg_length, sizeof(msg_length));

    p_global_arena_raw->current = tmp_connection_msg;
    p_global_arena_data->connection_msg.end_addr = (uint8_t *)p_global_arena_raw->current - 1;

    int count = 0;
    while (count < CONNECTION_POOL_SIZE) {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, BLOCK_EXECUTION);
        assert(nfds != -1);

        for (i = 0; i < nfds; i++) {
            SocketInfo *socket_info = (SocketInfo *)events[i].data.ptr;

            if (socket_info->type == DB_SOCKET) {
                if (events[i].events & EPOLLOUT) {
                    ssize_t bytes_sent = send(socket_info->fd, connection_msg, connection_msg_size, 0);
                    if (bytes_sent == -1 && errno == EAGAIN) {
                        /* If send buffer is full, try again later */
                        continue;
                    }

                    event.events = EPOLLIN | EPOLLET;
                    event.data.ptr = socket_info;
                    assert(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, socket_info->fd, &event) >= 0);
                } else if (events[i].events & EPOLLIN) {
                    char db_connection_response[KB(1)];
                    memset(db_connection_response, 0, sizeof(db_connection_response));

                    char *tmp_response = db_connection_response;
                    ssize_t read_stream = 0;

                    while (1) {
                        char *ptr = tmp_response + read_stream;

                        ssize_t incomming_stream_size = recv(socket_info->fd, ptr, sizeof(db_connection_response) - read_stream, 0);
                        if (incomming_stream_size == -1) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                break;
                            }
                        }

                        if (incomming_stream_size == 0) {
                            printf("Postgres server closed connection\n");

                            break;
                        }

                        read_stream += incomming_stream_size;

                        if (incomming_stream_size <= 0) {
                            break;
                        }

                        assert(read_stream < (ssize_t)sizeof(db_connection_response));
                    }

                    if (read_stream > 0) {
                        connection_pool[count].alive = 1;
                        count++;
                    }

                    /** TODO: Instead of printing raw bytes, decode to data structure. */
                    ssize_t j;
                    for (j = 0; j < read_stream; j++) {
                        printf("%c", (unsigned char)db_connection_response[j]);
                        if (j == read_stream - 1) {
                            printf("\n");
                        }
                    }
                }
            }
        }
    }
}

Arena *arena_init(size_t size) {
    Arena *arena = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(arena != NULL);

    memset(arena, 0, size);

    arena->size = size;
    arena->start = arena;
    arena->current = (uint8_t *)arena + sizeof(Arena);

    return arena;
}

void *arena_alloc(Arena *arena, size_t size) {
    if ((uint8_t *)arena->current + size > (uint8_t *)arena->start + arena->size) {
        assert(0);
    }

    void *ptr = arena->current;
    arena->current = (uint8_t *)arena->current + size;

    return ptr;
}

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
