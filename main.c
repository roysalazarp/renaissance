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
#define MAX_HTML_FILES 20
#define MAX_CONNECTIONS 100
#define MAX_QUEUING_REQUESTS MAX_CONNECTIONS
#define CONNECTION_POOL_SIZE 2

#define KB(value) ((value) * 1024)
#define PAGE_SIZE KB(4)

#define MAX_EVENTS 10

#define BLOCK_EXECUTION -1     /* The kernel can put the process to sleep until epoll_wait returns */
#define DONT_BLOCK_EXECUTION 0 /* Return inmediately */

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
    CharsBlock html_files_paths;
    CharsBlock components;
    CharsBlock html_templates;
    MemBlock connection_msg;
    char *styles;
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
} DBSocketInfo;

typedef struct {
    Client client;
    DBSocketInfo *connection;
} RequestQueue;

typedef struct {
    DBSocketInfo *connection;
    RequestQueue *queued;
} GenericContext;

typedef struct {
    GenericContext ctx;
    MemBlock users_id_query;
    CharsBlock users_id_query_response;
    CharsBlock http_response;
} HomeGetContext;

void sigint_handler(int signo);
void router(Arena *scratch_arena_raw);
void sign_up_create_user_post(int client_socket);
void sign_up_get(int client_socket);
void styles_get(Arena *scratch_arena_raw);
void home_get(Arena *scratch_arena_raw);
void not_found(int client_socket);
void locate_html_files(char *buffer, const char *base_path, uint8_t level, uint8_t *total_html_files, size_t *all_paths_length);
void url_decode(char **string);
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

volatile sig_atomic_t keep_running = 1;

Arena *_p_global_arena_raw;
GlobalArenaDataLookup *_p_global_arena_data;

int epoll_fd;
volatile int nfds;
struct epoll_event events[MAX_EVENTS];
struct epoll_event event;

#define to_index(i) (i + 1)
#define from_index(i) (i - 1)

DBSocketInfo connection_pool[CONNECTION_POOL_SIZE];
RequestQueue queue[MAX_QUEUING_REQUESTS];

jmp_buf client_socket_ctx;
jmp_buf db_socket_ctx;

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

    /** The .env file stores all necessary environment variables. */
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

    /* We respond to browser requests with HTML using a hypermedia approach. */
    char *html_files_paths = (char *)p_global_arena_raw->current;
    p_global_arena_data->html_files_paths.start_addr = p_global_arena_raw->current;
    char *base_path = get_value("TEMPLATES_FOLDER", p_global_arena_data->env);
    uint8_t html_files_count = 0;
    size_t all_paths_length = 0;
    locate_html_files(html_files_paths, base_path, 0, &html_files_count, &all_paths_length);

    p_global_arena_raw->current = (char *)p_global_arena_raw->current + all_paths_length;
    p_global_arena_data->html_files_paths.end_addr = (char *)p_global_arena_raw->current - 1;

    /* A Component is an HTML snippet that may include references to other HTML snippets, i.e., it is composable */
    char *components = (char *)p_global_arena_raw->current;
    p_global_arena_data->components.start_addr = p_global_arena_raw->current;
    char *tmp_components = components;

    char *tmp_html_files_paths = html_files_paths;
    uint8_t components_count = 0;

    i = 0;
    while (i < html_files_count) {
        char *file_content = NULL;
        long file_size = 0;
        read_file(&file_content, &file_size, tmp_html_files_paths); /** A .html file may contain multiple Components. */

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

        tmp_html_files_paths += strlen(tmp_html_files_paths) + 1; /* Move to next path */
        i++;
    }

    p_global_arena_raw->current = tmp_components;
    p_global_arena_data->components.end_addr = (char *)p_global_arena_raw->current - 1;

    /* An HTML template is essentially a Component that has been compiled with all its imports. */
    char *html_templates = (char *)p_global_arena_raw->current;
    p_global_arena_data->html_templates.start_addr = p_global_arena_raw->current;

    char *tmp_html_templates = html_templates;

    tmp_components = components;

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

    char *styles = (char *)p_global_arena_raw->current;
    p_global_arena_data->styles = p_global_arena_raw->current;
    char *styles_filepath = "./templates/index.css";
    char *styles_file_content = NULL;
    long styles_file_size = 0;
    read_file(&styles_file_content, &styles_file_size, styles_filepath); /** TODO: Minify CSS */
    memcpy(styles, styles_file_content, styles_file_size);
    p_global_arena_raw->current = styles + styles_file_size + 1;
    free(styles_file_content);
    styles_file_content = NULL;

    /**
     * Registers a signal handler for SIGINT (to terminate the process)
     * to exit the program gracefully for Valgrind to show the program report.
     */
    assert(signal(SIGINT, sigint_handler) != SIG_ERR);

    epoll_fd = epoll_create1(0);
    assert(epoll_fd != -1);

    uint16_t port = 8080;

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

    /*
    event.events = EPOLLIN | EPOLLET;
    */
    event.events = EPOLLIN;
    event.data.ptr = server_socket;
    assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) != -1);

    printf("Server listening on port: %d...\n", port);

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

    tmp_connection_msg += sizeof(u_int32_t);

    u_int32_t protocol_version = htonl(0x00030000);
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

    size_t lennn = tmp_connection_msg - connection_msg;
    u_int32_t msg_length = htonl((u_int32_t)lennn);
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
                    ssize_t bytes_sent = send(socket_info->fd, connection_msg, lennn, 0);
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

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    while (1) {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, BLOCK_EXECUTION);
        assert(nfds != -1);

        for (i = 0; i < nfds; i++) {
            SocketInfo *socket_info = (SocketInfo *)events[i].data.ptr;

            switch (socket_info->type) {
                case SERVER_SOCKET: {
                    if (events[i].events & EPOLLIN) {
                        int client_fd = accept(socket_info->fd, (struct sockaddr *)&client_addr, &client_addr_len);
                        assert(client_fd != -1);

                        int client_fd_flags = fcntl(client_fd, F_GETFL, 0);
                        assert(fcntl(client_fd, F_SETFL, client_fd_flags | O_NONBLOCK) != -1);

                        printf("initiated - client-fd: %d\n", client_fd);

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

                        if (setjmp(client_socket_ctx) == 0) {
                            router(scratch_arena_raw);
                        }

                        printf("\n");

                        break;
                    }

                    printf("Client socket only should receive EPOLLIN events\n");
                    assert(0);

                    break;
                }

                case DB_SOCKET: {
                    if (events[i].events & EPOLLIN) {
                        uint8_t j;
                        for (j = 0; j < CONNECTION_POOL_SIZE; j++) {
                            /** ready to read, should jump back to and might not be from the queue, ssize_t incomming_stream_size = recv */
                            if (connection_pool[j].socket.fd == socket_info->fd) {
                                if (((GenericContext *)(connection_pool[j].client.scratch_arena_data->local))->queued) {
                                    ((GenericContext *)(connection_pool[j].client.scratch_arena_data->local))->connection = &(connection_pool[j]);
                                }

                                longjmp(connection_pool[j].client.jmp_buf, to_index(j));
                            }
                        }

                    } else if (events[i].events & EPOLLOUT) {
                        if (queue[0].client.fd != 0) {
                            DBSocketInfo *db_socket = (DBSocketInfo *)socket_info;

                            uint8_t index = db_socket->index;
                            connection_pool[index].client = queue[0].client;

                            queue[0].connection = &(connection_pool[index]);

                            if (setjmp(db_socket_ctx) == 0) {
                                printf("gooooo\n");

                                longjmp(queue[to_index(0)].client.jmp_buf, 1);
                            }
                        }
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

ssize_t read_n(int sockfd, void *buf, size_t len) {
    size_t total = 0;
    ssize_t n;
    char *p = buf;
    while (total < len) {
        n = read(sockfd, p + total, len - total);
        if (n == -1) {
            return -1;
        }
        if (n == 0) {
            break;
        }
        total += n;
    }
    return total;
}

ssize_t write_all(int sockfd, const void *buf, size_t len) {
    size_t total = 0;
    ssize_t n;
    const char *p = buf;
    while (total < len) {
        n = write(sockfd, p + total, len - total);
        if (n == -1) {
            return -1;
        }
        total += n;
    }
    return total;
}

void router(Arena *scratch_arena_raw) {
    int i;

    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(SocketInfo)));

    int client_socket = scratch_arena_data->client_socket;

    printf("handling - client-fd: %d\n", client_socket);

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

            assert(0);

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
            }
        }

        if (incomming_stream_size <= 0) {
            /** TODOIMPORTANT: Make client_socket non-blocking, otherwise it will block when client request contains 0 bytes */
            printf("fd %d - Empty request\n", client_socket);
            return;
        }

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
        printf("terminated - client-fd: %d\n", client_socket);
    } else if (strncmp(url.start_addr, "/styles.css", strlen("/styles.css")) == 0 && strncmp(method.start_addr, "GET", method.length) == 0) {
        styles_get(scratch_arena_raw);
    } else if (strncmp(url.start_addr, "/ ", strlen("/ ")) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            home_get(scratch_arena_raw);
        }
    } else if (strncmp(url.start_addr, "/sign-up", strlen("/sign-up")) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            sign_up_get(client_socket);
        }
    } else if (strncmp(url.start_addr, "/sign-up/create-user", strlen("/sign-up/create-user")) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            sign_up_create_user_post(client_socket);
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

void sign_up_create_user_post(int client_socket) {
    char response[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

    if (send(client_socket, response, strlen(response), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(client_socket);
}

void sign_up_get(int client_socket) {
    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

    if (send(client_socket, response_headers, strlen(response_headers), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(client_socket);
}

void styles_get(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(SocketInfo)));

    int client_socket = scratch_arena_data->client_socket;

    char *css = _p_global_arena_data->styles;

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

    longjmp(client_socket_ctx, 1);
}

void home_get(Arena *scratch_arena_raw) {
    ScratchArenaDataLookup *scratch_arena_data = (ScratchArenaDataLookup *)((uint8_t *)scratch_arena_raw + (sizeof(Arena) + sizeof(SocketInfo)));
    scratch_arena_data->local = (HomeGetContext *)arena_alloc(scratch_arena_raw, sizeof(HomeGetContext));

    HomeGetContext *local = scratch_arena_data->local;

    int i;
    for (i = 0; i < CONNECTION_POOL_SIZE; i++) {
        if (connection_pool[i].alive && connection_pool[i].client.fd == 0) {

            connection_pool[i].client.fd = scratch_arena_data->client_socket;
            connection_pool[i].client.scratch_arena_raw = scratch_arena_raw;
            connection_pool[i].client.scratch_arena_data = scratch_arena_data;

            local->ctx.connection = &(connection_pool[i]);
            local->ctx.connection->client.scratch_arena_data = scratch_arena_data;

            break;
        }
    }

    if (local->ctx.connection == NULL) {
        printf("Didn't find available connection in pool\n");

        for (i = 0; i < MAX_QUEUING_REQUESTS; i++) {
            if (queue[i].client.fd == 0) {

                queue[i].client.fd = scratch_arena_data->client_socket;
                queue[i].client.scratch_arena_raw = scratch_arena_raw;
                queue[i].client.scratch_arena_data = scratch_arena_data;
                queue[i].client.scratch_arena_data->local = local;

                local->ctx.queued = &(queue[i]);

                int r = setjmp(queue[i].client.jmp_buf);
                if (r == 0) {
                    longjmp(client_socket_ctx, 1);
                }

                scratch_arena_data = queue[from_index(r)].client.scratch_arena_data;
                scratch_arena_data->local = queue[from_index(r)].client.scratch_arena_data->local;
                local = scratch_arena_data->local;

                ((HomeGetContext *)scratch_arena_data->local)->ctx.connection = queue[from_index(r)].connection;
                scratch_arena_raw = scratch_arena_data->arena;

                break;
            }
        }
    }

    char message_type = 'Q';
    char users_id_query_local[] = "SELECT id FROM app.users;";
    int32_t message_length = htonl((int32_t)(sizeof(users_id_query_local)) + (int32_t)(sizeof(int32_t)));
    size_t users_id_query_length = sizeof(char) + sizeof(int32_t) + (strlen(users_id_query_local) + 1);

    uint8_t *users_id_query = arena_alloc(scratch_arena_raw, users_id_query_length);
    memcpy(users_id_query, &message_type, sizeof(char));
    memcpy(users_id_query + sizeof(char), &message_length, sizeof(int32_t));
    memcpy(users_id_query + sizeof(char) + sizeof(int32_t), &users_id_query_local, (strlen(users_id_query_local) + 1));

    ((HomeGetContext *)scratch_arena_data->local)->users_id_query.start_addr = users_id_query;
    ((HomeGetContext *)scratch_arena_data->local)->users_id_query.end_addr = users_id_query + users_id_query_length;

    size_t msg_length = ((HomeGetContext *)scratch_arena_data->local)->users_id_query.end_addr - ((HomeGetContext *)scratch_arena_data->local)->users_id_query.start_addr;
    ssize_t bytes_sent = send(((HomeGetContext *)scratch_arena_data->local)->ctx.connection->socket.fd, ((HomeGetContext *)scratch_arena_data->local)->users_id_query.start_addr, msg_length, 0);
    if (bytes_sent == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /** ? */
            printf("here!?\n");
        }
    }

retry:
    ((HomeGetContext *)scratch_arena_data->local)->users_id_query_response.start_addr = (char *)scratch_arena_raw->current;
    ssize_t read_stream = 0;
    while (1) {
        char *ptr = ((HomeGetContext *)scratch_arena_data->local)->users_id_query_response.start_addr + read_stream;

        ssize_t incomming_stream_size = recv(((HomeGetContext *)scratch_arena_data->local)->ctx.connection->socket.fd, ptr, KB(1) - read_stream, 0);
        if (incomming_stream_size == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                event.events = EPOLLIN | EPOLLET;
                event.data.ptr = &(((HomeGetContext *)scratch_arena_data->local)->ctx.connection->socket);
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ((HomeGetContext *)scratch_arena_data->local)->ctx.connection->socket.fd, &event);

                int r = setjmp(((HomeGetContext *)scratch_arena_data->local)->ctx.connection->client.jmp_buf);
                if (r == 0) {
                    longjmp(client_socket_ctx, 1);
                }

                scratch_arena_data = connection_pool[from_index(r)].client.scratch_arena_data;
                scratch_arena_raw = scratch_arena_data->arena;

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

        ((HomeGetContext *)scratch_arena_data->local)->users_id_query_response.end_addr = ((HomeGetContext *)scratch_arena_data->local)->users_id_query_response.start_addr + read_stream;

        ssize_t j;
        for (j = 0; j < read_stream; j++) {
            printf("%c", (unsigned char)((HomeGetContext *)scratch_arena_data->local)->users_id_query_response.start_addr[j]);
            if (j == read_stream - 1) {
                printf("\n");
            }
        }

        break;
    }

    memset(&(((HomeGetContext *)scratch_arena_data->local)->ctx.connection->client), 0, sizeof(Client));
    /*
    ((HomeGetContext *)scratch_arena_data->local)->ctx.connection->client.fd = 0;
    memset(((HomeGetContext *)scratch_arena_data->local)->ctx.connection->client.jmp_buf, 0, sizeof(jmp_buf));
    */

    event.events = EPOLLOUT | EPOLLET;
    event.data.ptr = &(((HomeGetContext *)scratch_arena_data->local)->ctx.connection->socket);
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ((HomeGetContext *)scratch_arena_data->local)->ctx.connection->socket.fd, &event);

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
    printf("terminated - client-fd: %d\n", scratch_arena_data->client_socket);

    h_count++;

    printf("handled requests: %d\n", h_count);

    if (((HomeGetContext *)scratch_arena_data->local)->ctx.queued == NULL) {
        arena_reset(scratch_arena_raw, sizeof(Arena) + sizeof(ScratchArenaDataLookup));
        longjmp(client_socket_ctx, 1);
    } else {
        ((HomeGetContext *)scratch_arena_data->local)->ctx.queued->client.fd = 0;
        memset(((HomeGetContext *)scratch_arena_data->local)->ctx.queued->client.jmp_buf, 0, sizeof(jmp_buf));

        arena_reset(scratch_arena_raw, sizeof(Arena) + sizeof(ScratchArenaDataLookup));
        longjmp(db_socket_ctx, 1);
    }
}

void not_found(int client_socket) {
    char response[] = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
                      "<html><body><h1>404 Not Found</h1></body></html>";

    if (send(client_socket, response, strlen(response), 0) == -1) {
        /** TODO: Write error to logs */
    }

    close(client_socket);
}

void url_decode(char **string) {
    char *out = *string;
    size_t len = strlen(*string);

    size_t i;
    for (i = 0; i < len; i++) {
        if ((*string)[i] == '%' && i + 2 < len && isxdigit((*string)[i + 1]) && isxdigit((*string)[i + 2])) {
            char c = hex_to_char((*string)[i + 1]) * 16 + hex_to_char((*string)[i + 2]);
            *out++ = c;
            i += 2;
        } else if ((*string)[i] == '+') {
            *out++ = ' ';
        } else {
            *out++ = (*string)[i];
        }
    }

    *out = '\0';
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
void locate_html_files(char *buffer, const char *base_path, uint8_t level, uint8_t *total_html_files, size_t *all_paths_length) {
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
                locate_html_files(buffer, path, level + 1, total_html_files, all_paths_length);
            } else {
                entry_name_length = strlen(entry->d_name);
                if (entry_name_length > 5 && strcmp(entry->d_name + entry_name_length - 5, ".html") == 0) {
                    assert(*total_html_files < MAX_HTML_FILES);
                    size_t path_len = strlen(path);
                    strcpy(buffer, path);
                    buffer[path_len] = '\0';
                    buffer += (path_len + 1);
                    (*all_paths_length) = (*all_paths_length) + (path_len + 1);
                    (*total_html_files)++;
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