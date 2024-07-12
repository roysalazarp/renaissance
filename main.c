#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <libpq-fe.h>
#include <linux/limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * In development mode, set PANIC to 1 to force program crash on error.
 * In production, set PANIC to 0 and try to recover from error.
 * TODO: This variable should be set at compile time, not hardcoded.
 */
#define PANIC 1

#define MAX_LINE_LENGTH 160
#define MAX_ABSOLUTE_PATH_LENGTH 200
#define MAX_PATH_LENGTH 200
#define MAX_HTML_FILES 20
#define MAX_ID_LENGTH 80
#define MAX_ERROR_MSG_LENGTH 248

#define MAX_CONNECTIONS 100
#define PROJECT_ROOT_PATH "/workspaces/web-server/"

typedef struct ClientSocketQueueNode {
    struct ClientSocketQueueNode *next;
    int *client_socket;
} ClientSocketQueueNode;

typedef struct {
    char message[MAX_ERROR_MSG_LENGTH];
    int8_t panic;
    /** TODO: add more fields here that can help to reproduce the error easily */
} Error;

typedef struct {
    char DB_NAME[12];
    char DB_USER[16];
    char DB_PASSWORD[9];
    char DB_HOST[10];
    char DB_PORT[5];
} ENV;

#define MAX_HTTP_URL_LENGTH 248
#define MAX_HTTP_METHOD_LENGTH 16
#define MAX_HTTP_VERSION_LENGTH 16

typedef struct {
    char url[MAX_HTTP_URL_LENGTH];
    char method[MAX_HTTP_METHOD_LENGTH];
    char http_version[MAX_HTTP_VERSION_LENGTH];
    char *query_params;
    char *headers;
    char *body;
} HttpRequest;

typedef struct Template Template;

#define MAX_VALUE_NAME_LENGTH 80
#define MAX_VALUE_REFERENCE_LENGTH 88

typedef struct {
    char name[MAX_VALUE_NAME_LENGTH];
    char reference[MAX_VALUE_REFERENCE_LENGTH];
} Value;

#define MAX_BLOCK_NAME_LENGTH 80
typedef struct {
    char name[MAX_BLOCK_NAME_LENGTH];
    struct {
        char *content;
        unsigned int start;
        unsigned int end;
    } html;
    struct {
        char *reference;
        unsigned int start;
        unsigned int end;
    } lookup;
    Value *values;
    enum { FOR, IF } type;
    uint8_t values_length;
} ActionBlock;

typedef struct {
    struct {
        char *reference;
        unsigned int start;
        unsigned int end;
    } lookup;
    Template *component;
} Component;

struct Template {
    char *name;
    char *composed_html_content;
    char *html_content;
    size_t html_content_length;
    ActionBlock *blocks;
    Component *components;
    Value *values;
    uint8_t blocks_length;
    uint8_t components_length;
    uint8_t values_length;
};

void sigint_handler(int signo);
Error router(void *p_client_socket, uint8_t thread_index);
void *thread_function(void *arg);
void enqueue_client_socket(int *client_socket);
void *dequeue_client_socket();
Error sign_up_create_user_post(int client_socket, HttpRequest *request, uint8_t thread_index);
Error sign_up_get(int client_socket, HttpRequest *request, uint8_t thread_index);
Error home_get(int client_socket, HttpRequest *request, uint8_t thread_index);
Error read_request(char **request_buffer, int client_socket);
Error parse_http_request(HttpRequest *parsed_http_request, const char *http_request);
void http_request_free(HttpRequest *parsed_http_request);
Error not_found(int client_socket, HttpRequest *request);
Error load_values_from_file(void *structure, const char *project_root_path, const char *file_path_relative_to_project_root);
void print_query_result(PGresult *query_result);
Error read_file(char **buffer, char *absolute_file_path, size_t file_size);
Error resolve_component_imports(Template *template);
Error get_html_files_paths(char **html_files_paths, const char *base_path, uint8_t level, uint8_t *total_html_files);
void free_html_files_paths(char **html_files_paths);
void free_all_templates(Template **templates, uint8_t number_of_blocks);
Error calculate_file_size(long *file_size, char *absolute_file_path);
Error url_decode(char **string);
Error parse_value(char buffer[], const char key_name[], char *string);
char hex_to_char(char c);

volatile sig_atomic_t keep_running = 1;

#define POOL_SIZE 1

PGconn *conn_pool[POOL_SIZE];

pthread_t thread_pool[POOL_SIZE];
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t thread_condition_var = PTHREAD_COND_INITIALIZER;

ClientSocketQueueNode *head_client_socket_queue = NULL;
ClientSocketQueueNode *tail_client_socket_queue = NULL;

Template **templates;

#define BLOCK_ID_START "{{ block \""
#define BLOCK_ID_END "\" }}"
#define ID_START "{{ "
#define SLOT_ID_START "{{ slot"
#define TEMPLATE_ID_START "{{ template \""
#define TEMPLATE_ID_END "\" }}"
#define OPTIONAL_NAME_ID_START "{{ ."
#define FOR_ID_START "{{ for"
#define END_ID "{{ end }}"

int main() {
    int retval = 0;

    uint8_t i;
    char *temp;

    Error error = {0};

    /**
     * Registers a signal handler for SIGINT (to terminate the process)
     * to exit the program gracefully for Valgrind to show the program report.
     */
    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        fprintf(stderr, "Failed to set up signal handler for SIGINT\nError code: %d\n", errno);
        retval = -1;
        goto main_exit;
    }

    /* ⬇ Find all HTML files down from a given base directory ⬇ */

    char **html_files_paths = (char **)calloc(MAX_HTML_FILES, sizeof(char *));
    if (html_files_paths == NULL) {
        fprintf(stderr, "Failed to allocate memory for html_files_paths\nError code: %d\n", errno);
        retval = -1;
        goto main_exit;
    }

    for (i = 0; i < MAX_HTML_FILES; i++) {
        html_files_paths[i] = (char *)calloc(MAX_PATH_LENGTH, sizeof(char));

        if (html_files_paths[i] == NULL) {
            free_html_files_paths(html_files_paths);
            fprintf(stderr, "Failed to allocate memory for html_files_paths[%d]\nError code: %d\n", i, errno);
            retval = -1;
            goto main_exit;
        }
    }

    const char *base_path = "./templates";
    uint8_t total_html_files = 0;
    if ((error = get_html_files_paths(html_files_paths, base_path, 0, &total_html_files)).panic) {
        free_html_files_paths(html_files_paths);
        retval = -1;
        goto main_exit;
    }

    long html_files_paths_lengths[MAX_HTML_FILES];

    for (i = 0; i < MAX_HTML_FILES; i++) {
        html_files_paths_lengths[i] = 0;
    }

    long templates_collection_length = 0;
    for (i = 0; i < total_html_files; i++) {
        long html_file_length = 0;
        if ((error = calculate_file_size(&html_file_length, html_files_paths[i])).panic) {
            free_html_files_paths(html_files_paths);
            retval = -1;
            goto main_exit;
        }

        html_files_paths_lengths[i] = html_file_length;
        templates_collection_length = templates_collection_length + html_file_length;
    }

    /* ⬇ Join all HTML blocks into a single 'templates_collection' buffer ⬇ */

    char *templates_collection = (char *)calloc(templates_collection_length + 1, sizeof(char));
    if (templates_collection == NULL) {
        free_html_files_paths(html_files_paths);
        fprintf(stderr, "Failed to allocate memory for templates_collection\nError code: %d\n", errno);
        retval = -1;
        goto main_exit;
    }

    temp = templates_collection;
    for (i = 0; i < MAX_HTML_FILES; i++) {
        if (html_files_paths_lengths[i] == 0) {
            break;
        }

        if ((error = read_file(&temp, html_files_paths[i], html_files_paths_lengths[i])).panic) {
            free_html_files_paths(html_files_paths);
            retval = -1;
            goto main_cleanup_templates_collection;
        }

        temp += html_files_paths_lengths[i];
    }

    templates_collection[templates_collection_length] = '\0';

    temp = NULL;

    free_html_files_paths(html_files_paths); /** Clear from memory information about server directories */

    /* ⬇ Create 'Template' instances for each HTML block in 'templates_collection' ⬇ */
    /* These instances will contain useful data and information that will help reduce HTML rendering work during request processing later on */

    temp = templates_collection;
    uint8_t number_of_blocks = 0;

    while ((temp = strstr(temp, BLOCK_ID_START)) != NULL) {
        number_of_blocks++;
        temp += strlen(BLOCK_ID_START);
    }

    temp = NULL;

    templates = (Template **)calloc(number_of_blocks, sizeof(Template *));
    if (templates == NULL) {
        fprintf(stderr, "Failed to allocate memory for templates\nError code: %d\n", errno);
        retval = -1;
        goto main_cleanup_templates_collection;
    }

    for (i = 0; i < number_of_blocks; i++) {
        templates[i] = (Template *)malloc(sizeof(Template));

        if (templates[i] == NULL) {
            fprintf(stderr, "Failed to allocate memory for templates[%d]\nError code: %d\n", i, errno);
            retval = -1;
            goto main_cleanup_templates;
        }

        templates[i]->name = NULL;
        templates[i]->composed_html_content = NULL;
        templates[i]->html_content = NULL;
        templates[i]->html_content_length = 0;
        templates[i]->blocks = NULL;
        templates[i]->components = NULL;
        templates[i]->values = NULL;
        templates[i]->blocks_length = 0;
        templates[i]->components_length = 0;
        templates[i]->values_length = 0;
    }

    /* ⬇⬇ Set 'name' for all 'Template' instances ⬇⬇ */

    temp = templates_collection;
    i = 0;
    while ((temp = strstr(temp, BLOCK_ID_START)) != NULL) {
        temp += strlen(BLOCK_ID_START);

        uint8_t block_name_length = 0;
        size_t j;
        for (j = 0; temp[j] != '\0'; j++) {
            if (temp[j] == '\"') {
                break;
            }

            block_name_length++;
        }

        templates[i]->name = calloc(block_name_length + 1, sizeof(char));
        if (templates[i]->name == NULL) {
            fprintf(stderr, "Failed to allocate memory for templates[%d]->name\nError code: %d\n", i, errno);
            retval = -1;
            goto main_cleanup_templates;
        }

        if (memcpy(templates[i]->name, temp, block_name_length) == NULL) {
            fprintf(stderr, "Failed to copy into templates[%d]->name\nError code: %d\n", i, errno);
            retval = -1;
            goto main_cleanup_templates;
        }

        templates[i]->name[block_name_length] = '\0';

        i++;
    }

    temp = NULL;

    /* ⬇⬇ Copy HTML block from 'templates_collection' into each 'Template' instance that matches name ⬇⬇ */

    for (i = 0; i < number_of_blocks; i++) {
        uint8_t block_name_length = (uint8_t)strlen(templates[i]->name);
        uint8_t block_id_length = strlen(BLOCK_ID_START) + block_name_length + strlen(BLOCK_ID_END) + 1;

        if (MAX_ID_LENGTH < block_id_length) {
            fprintf(stderr, "block_id_length(%d) should not exceed MAX_ID_LENGTH(%d), you might want to increase MAX_ID_LENGTH\nError code: %d\n", block_id_length, MAX_ID_LENGTH, errno);
            retval = -1;
            goto main_cleanup_templates;
        }

        char block_id[MAX_ID_LENGTH];

        if (sprintf(block_id, "%s%s%s", BLOCK_ID_START, templates[i]->name, BLOCK_ID_END) != (block_id_length - 1)) {
            fprintf(stderr, "Failed to copy into block_id\nError code: %d\n", errno);
            retval = -1;
            goto main_cleanup_templates;
        }

        temp = templates_collection;
        char *block_end = NULL;
        while ((temp = strstr(temp, block_id)) != NULL) {
            uint8_t inside_nested = 0;

            /**
             * Now that we have identified the block_id `{{ block "some_name" }}`,
             * we proceed to locate its closing tag `{{ end }}`. Start by searching for the next `{{ `
             */
            char *temp2 = temp;
            while ((temp2 = strstr(temp2 + strlen(ID_START), ID_START)) != NULL) {
                /* clang-format off */
                if (strncmp(temp2, SLOT_ID_START, strlen(SLOT_ID_START)) == 0 || 
                    strncmp(temp2, TEMPLATE_ID_START, strlen(TEMPLATE_ID_START)) == 0 || 
                    strncmp(temp2, OPTIONAL_NAME_ID_START, strlen(OPTIONAL_NAME_ID_START)) == 0) {
                    continue;
                }
                /* clang-format on */

                if (strncmp(temp2, FOR_ID_START, strlen(FOR_ID_START)) == 0) {
                    inside_nested++;
                    continue;
                }

                if (strncmp(temp2, END_ID, strlen(END_ID)) == 0) {
                    if (inside_nested == 0) {
                        block_end = temp2;
                        break;
                    }

                    inside_nested--;
                }
            }

            size_t html_content_length = block_end - (temp + block_id_length);
            templates[i]->html_content = calloc(html_content_length + 1, sizeof(char));
            if (templates[i]->html_content == NULL) {
                fprintf(stderr, "Failed to allocate memory for templates[%d]->html_content\nError code: %d\n", i, errno);
                retval = -1;
                goto main_cleanup_templates;
            }

            templates[i]->html_content_length = html_content_length;

            if (memcpy(templates[i]->html_content, temp + block_id_length, html_content_length) == NULL) {
                fprintf(stderr, "Failed to copy into templates[%d]->html_content\nError code: %d\n", i, errno);
                retval = -1;
                goto main_cleanup_templates;
            }

            break; /** Stop at the first occurrence */
        }

        temp = NULL;
    }

    /* ⬇⬇ Link 'Template' instances when one uses another as a component ⬇⬇ */

    for (i = 0; i < number_of_blocks; i++) {
        Template *template = templates[i];

        temp = template->html_content;
        uint8_t number_of_component_imports = 0;

        while ((temp = strstr(temp, TEMPLATE_ID_START)) != NULL) {
            number_of_component_imports++;
            temp += strlen(TEMPLATE_ID_START);
        }

        temp = NULL;

        if (number_of_component_imports == 0) {
            continue;
        }

        template->components_length = number_of_component_imports;

        template->components = malloc(template->components_length * sizeof(Template *));
        if (template->components == NULL) {
            fprintf(stderr, "Failed to allocate memory for template->components\nError code: %d\n", errno);
            retval = -1;
            goto main_cleanup_templates;
        }

        temp = template->html_content;

        uint8_t j;
        for (j = 0; j < template->components_length; j++) {
            char *component_name_start = NULL;
            char *component_name_end = NULL;
            uint8_t component_name_length = 0;

            while ((temp = strstr(temp, TEMPLATE_ID_START)) != NULL) {
                temp += strlen(TEMPLATE_ID_START);

                component_name_start = temp;
                component_name_end = strchr(component_name_start, '"');
                if (component_name_end == NULL) {
                    fprintf(stderr, "Component import name for %s block is missing closing \".\nError code: %d\n", templates[i]->name, errno);
                    retval = -1;
                    goto main_cleanup_templates;
                }

                component_name_length = component_name_end - component_name_start;

                break; /** Stop at the first occurrence */
            }

            uint8_t k;
            for (k = 0; k < number_of_blocks; k++) {
                if (strncmp(templates[k]->name, component_name_start, component_name_length) == 0) {
                    template->components[j].component = templates[k];

                    uint8_t id_length = (uint8_t)strlen(TEMPLATE_ID_START) + component_name_length + (uint8_t)strlen(TEMPLATE_ID_END);

                    template->components[j].lookup.reference = calloc(id_length + 1, sizeof(char));
                    if (template->components[j].lookup.reference == NULL) {
                        fprintf(stderr, "Failed to allocate memory for template->components[%d].lookup.reference\nError code: %d\n", j, errno);
                        retval = -1;
                        goto main_cleanup_templates;
                    }

                    if (MAX_ID_LENGTH < id_length) {
                        fprintf(stderr, "id_length(%d) should not exceed MAX_ID_LENGTH(%d), you might want to increase MAX_ID_LENGTH\nError code: %d\n", id_length, MAX_ID_LENGTH, errno);
                        retval = -1;
                        goto main_cleanup_templates;
                    }

                    char id[MAX_ID_LENGTH];

                    if (sprintf(id, "%s%s%s", TEMPLATE_ID_START, component_name_start, TEMPLATE_ID_END) != (strlen(TEMPLATE_ID_START) + strlen(component_name_start) + strlen(TEMPLATE_ID_END))) {
                        fprintf(stderr, "Failed to copy into id\nError code: %d\n", errno);
                        retval = -1;
                        goto main_cleanup_templates;
                    }

                    if (memcpy(template->components[j].lookup.reference, id, id_length) == NULL) {
                        fprintf(stderr, "Failed to copy into template->components[%d].lookup.reference\nError code: %d\n", j, errno);
                        retval = -1;
                        goto main_cleanup_templates;
                    }

                    template->components[j].lookup.reference[id_length] = '\0';
                }
            }
        }

        temp = NULL;
    }

    /* ⬇⬇ Render HTML blocks with imported components for each 'Template' instance ⬇⬇ */

    for (i = 0; i < number_of_blocks; i++) {
        Template *template = templates[i];

        if (template->composed_html_content == NULL) {
            template->composed_html_content = (char *)calloc(template->html_content_length, sizeof(char));
            if (template->composed_html_content == NULL) {
                fprintf(stderr, "Failed to allocate memory for template->composed_html_content\nError code: %d\n", errno);
                retval = -1;
                goto main_cleanup_templates;
            }

            if (memcpy(template->composed_html_content, template->html_content, (template->html_content_length - 1)) == NULL) {
                fprintf(stderr, "Failed to copy into template->composed_html_content\nError code: %d\n", errno);
                retval = -1;
                goto main_cleanup_templates;
            }

            template->composed_html_content[template->html_content_length - 1] = '\0';
        }

        if (template->components_length == 0) {
            continue;
        }

        if ((error = resolve_component_imports(template)).panic) {
            retval = -1;
            goto main_cleanup_templates;
        }
    }

    ENV env = {0};
    const char env_file_path[] = ".env";
    if ((error = load_values_from_file(&env, PROJECT_ROOT_PATH, env_file_path)).panic) {
        retval = -1;
        goto main_cleanup_templates;
    }

    uint16_t port = 8080;

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        fprintf(stderr, "Failed to create server socket\nError code: %d\n", errno);
        retval = -1;
        goto main_cleanup_templates;
    }

    int optname = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optname, sizeof(int)) == -1) {
        fprintf(stderr, "Failed to set port address for immediately re-use after the socket is closed\nError code: %d\n", errno);
        retval = -1;
        goto main_cleanup_socket;
    }

    /** Configure server address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;         /** IPv4 */
    server_addr.sin_port = htons(port);       /** Convert the port number from host byte order to network byte order (big-endian) */
    server_addr.sin_addr.s_addr = INADDR_ANY; /** Listen on all available network interfaces (IPv4 addresses) */

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        fprintf(stderr, "Failed to bind server socket to adress(%d) and port(%d)\nError code: %d\n", server_addr.sin_addr.s_addr, server_addr.sin_port, errno);
        retval = -1;
        goto main_cleanup_socket;
    }

    if (listen(server_socket, MAX_CONNECTIONS) == -1) {
        fprintf(stderr, "Failed to set up server socker to listen for incoming connections\nError code: %d\n", errno);
        retval = -1;
        goto main_cleanup_socket;
    }

    printf("Server listening on port: %d...\n", port);

    const char *db_connection_keywords[] = {"dbname", "user", "password", "host", "port", NULL};
    const char *db_connection_values[6];
    db_connection_values[0] = env.DB_NAME;
    db_connection_values[1] = env.DB_USER;
    db_connection_values[2] = env.DB_PASSWORD;
    db_connection_values[3] = env.DB_HOST;
    db_connection_values[4] = env.DB_PORT;
    db_connection_values[5] = NULL;

    /** Create thread pool */
    for (i = 0; i < POOL_SIZE; i++) {
        /**
         * Thread might take some time time to create, but 'i' will keep mutating as the program runs,
         * storing the value of 'i' in the heap at the time of iterating ensures that thread_function
         * receives the correct value even when 'i' has moved on.
         */
        unsigned short *p_iteration = malloc(sizeof(unsigned short));
        *p_iteration = i;
        if (pthread_create(&thread_pool[*p_iteration], NULL, &thread_function, p_iteration) != 0) {
            fprintf(stderr, "Failed to create thread at iteration n° %d\nError code: %d\n", *p_iteration, errno);
            retval = -1;
            goto main_cleanup_threads;
        }
    }

    for (i = 0; i < POOL_SIZE; i++) {
        conn_pool[i] = PQconnectdbParams(db_connection_keywords, db_connection_values, 0);
        if (PQstatus(conn_pool[i]) != CONNECTION_OK) {
            fprintf(stderr, "Failed to create db connection pool at iteration n° %d\nError code: %d\n", i, errno);
            retval = -1;
            goto main_cleanup;
        }
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof client_addr;

        /** The while loop will wait at accept for a new client to connect */
        int client_socket;
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);

        /**
         * When a signal to exit the program is received, 'accept' will error with -1. To verify that
         * client_socket being -1 isn't because of program termination, check whether the program
         * has received a signal to exit.
         */
        if (keep_running == 0) {
            /** Send signal to threads to resume execusion so they can proceed to cleanup */
            pthread_cond_signal(&thread_condition_var);
            retval = 0;
            goto main_cleanup;
        }

        /** At this point, we know that client_socket being -1 wouldn't have been caused by program termination */
        if (client_socket == -1) {
            fprintf(stderr, "Failed to create client socket\nError code: %d\n", errno);
            retval = -1;
            goto main_cleanup;
        }

        /**
         * Store fd number for client socket in the heap so it can be pointed by a queue data structure
         * and used when it is needed.
         */
        int *p_client_socket = malloc(sizeof(int));
        *p_client_socket = client_socket;

        if (pthread_mutex_lock(&thread_mutex) != 0) {
            fprintf(stderr, "Failed to lock pthread mutex\nError code: %d\n", errno);
            retval = -1;
            goto main_cleanup;
        }

        printf("- New request: enqueue_client_socket client socket fd %d\n", *p_client_socket);
        enqueue_client_socket(p_client_socket);

        if (pthread_cond_signal(&thread_condition_var) != 0) {
            fprintf(stderr, "Failed to send pthread signal\nError code: %d\n", errno);
            retval = -1;
            goto main_cleanup;
        }

        if (pthread_mutex_unlock(&thread_mutex) != 0) {
            fprintf(stderr, "Failed to unlock pthread mutex\nError code: %d\n", errno);
            retval = -1;
            goto main_cleanup;
        }
    }

main_cleanup:
    for (i = 0; i < POOL_SIZE; i++) {
        PQfinish(conn_pool[i]);
    }

main_cleanup_threads:
    for (i = 0; i < POOL_SIZE; i++) {
        /**
         * At this point, the variable 'keep_running' is 0.
         * Signal all threads to resume execution to perform cleanup.
         */
        pthread_cond_signal(&thread_condition_var);
    }

    for (i = 0; i < POOL_SIZE; i++) {
        printf("(Thread %d) Cleaning up thread %lu\n", i, thread_pool[i]);

        if (pthread_join(thread_pool[i], NULL) != 0) {
            fprintf(stderr, "Failed to join thread at position %d in the thread pool\nError code: %d\n", i, errno);
        }
    }

main_cleanup_socket:
    close(server_socket);

main_cleanup_templates:
    free_all_templates(templates, number_of_blocks);

main_cleanup_templates_collection:
    free(templates_collection);
    templates_collection = NULL;

main_exit:
    printf("%s\n", error.message);

    return retval;
}

void free_all_templates(Template **templates, uint8_t number_of_blocks) {
    uint8_t i;
    for (i = 0; i < number_of_blocks; i++) {
        free(templates[i]->name);
        templates[i]->name = NULL;

        free(templates[i]->composed_html_content);
        templates[i]->composed_html_content = NULL;

        free(templates[i]->html_content);
        templates[i]->html_content = NULL;

        uint8_t j;
        for (j = 0; j < templates[i]->blocks_length; j++) {
            /** TODO: Free templates[i]->blocks[j] members */
        }

        free(templates[i]->blocks);
        templates[i]->blocks = NULL;

        for (j = 0; j < templates[i]->components_length; j++) {
            /** TODO: Free templates[i]->components[j] members */
        }

        free(templates[i]->components);
        templates[i]->components = NULL;

        for (j = 0; j < templates[i]->values_length; j++) {
            /** TODO: Free templates[i]->values[j] members */
        }

        free(templates[i]->values);
        templates[i]->values = NULL;

        free(templates[i]);
        templates[i] = NULL;
    }

    free(templates);
    templates = NULL;
}

void *thread_function(void *arg) {
    Error error = {0};
    uint8_t *p_thread_index = (uint8_t *)arg;
    pthread_t tid = pthread_self();
    printf("(Thread %d) Setting up thread %lu\n", *p_thread_index, tid);

    while (1) {
        int *p_client_socket;

        if (pthread_mutex_lock(&thread_mutex) != 0) {
            /** TODO: cleanup */
        }

        /** Check queue for client request */
        if ((p_client_socket = dequeue_client_socket()) == NULL) {
            /** At this point, we know the queue was empty, so hold thread execusion */
            pthread_cond_wait(&thread_condition_var, &thread_mutex); /** On hold, waiting to receive a signal... */
            /** Signal to proceed with execusion has been sent */

            if (keep_running == 0) {
                pthread_mutex_unlock(&thread_mutex);
                goto out;
            }

            p_client_socket = dequeue_client_socket();
            printf("(Thread %d) Dequeueing(received signal)...\n", *p_thread_index);
            goto skip_print;
        }

        printf("(Thread %d) Dequeueing...\n", *p_thread_index);

    skip_print:

        if (pthread_mutex_unlock(&thread_mutex) != 0) {
            /** TODO: cleanup */
        }

        if (p_client_socket != NULL) {
            if ((error = router(p_client_socket, *p_thread_index)).panic) {
                break;
            }
        }
    }

out:
    printf("(Thread %d) Out of while loop\n", *p_thread_index);

    free(p_thread_index);
    p_thread_index = NULL;

    return NULL;
}

Error resolve_component_imports(Template *template) {
    Error error = {0};

    uint8_t z;
    for (z = 0; z < template->components_length; z++) {
        Component *component = &(template->components[z]);

        if (component->component->composed_html_content == NULL) {
            component->component->composed_html_content = (char *)calloc(component->component->html_content_length, sizeof(char));
            if (component->component->composed_html_content == NULL) {
                sprintf(error.message, "Failed to allocate memory for component->component->composed_html_content. Error code: %d", errno);
                error.panic = 1;
                return error;
            }

            if (memcpy(component->component->composed_html_content, component->component->html_content, (component->component->html_content_length - 1)) == NULL) {
                sprintf(error.message, "Failed to copy into component->component->composed_html_content. Error code: %d", errno);
                error.panic = 1;
                return error;
            }

            component->component->composed_html_content[component->component->html_content_length - 1] = '\0';
        }

        if ((error = resolve_component_imports(component->component)).panic) {
            error.panic = 1;
            return error;
        }

        char *after_address;
        if ((after_address = strstr(template->composed_html_content, component->lookup.reference)) == NULL) {
            /** NOTE: did it not find it because it was already handled or because it didn't exist in the first place ??? */

            return error;
        }

        size_t component_lookup_reference_length = strlen(component->lookup.reference);

        size_t child_component_reference_start = after_address - template->composed_html_content;
        after_address += component_lookup_reference_length;
        size_t after_length = strlen(after_address) + 1;

        char *after = (char *)calloc(after_length, sizeof(char));
        if (after == NULL) {
            sprintf(error.message, "Failed to allocate memory for after. Error code: %d", errno);
            error.panic = 1;
            return error;
        }

        after[after_length - 1] = '\0';

        if (memcpy(after, after_address, after_length) == NULL) {
            sprintf(error.message, "Failed to copy into after. Error code: %d", errno);
            error.panic = 1;
            return error;
        }

        template->composed_html_content = (char *)realloc(template->composed_html_content, (child_component_reference_start + strlen(component->component->composed_html_content) + after_length) * sizeof(char));
        if (template->composed_html_content == NULL) {
            sprintf(error.message, "Failed to re-allocate memory for template->composed_html_content. Error code: %d", errno);
            error.panic = 1;
            return error;
        }

        memmove(template->composed_html_content + child_component_reference_start + strlen(component->component->composed_html_content), after, after_length);
        memcpy(template->composed_html_content + child_component_reference_start, component->component->composed_html_content, strlen(component->component->composed_html_content));

        free(after);
        after = NULL;
    }

    return error;
}

Error router(void *p_client_socket, uint8_t thread_index) {
    Error error = {0};

    /**
     * At this point we don't need to hold the client_socket in heap anymore, we can work
     * with it in the stack from now on
     */
    int client_socket = *((int *)p_client_socket);

    free(p_client_socket);
    p_client_socket = NULL;

    char *request = NULL;
    if ((error = read_request(&request, client_socket)).panic) {
        goto router_exit;
    }

    if (strlen(request) == 0) {
        printf("Request is empty\n");
        goto router_cleanup_request;
    }

    HttpRequest parsed_http_request = {0};
    if ((error = parse_http_request(&parsed_http_request, request)).panic) {
        goto router_cleanup_request;
    }

    if (strcmp(parsed_http_request.url, "/") == 0) {
        if (strcmp(parsed_http_request.method, "GET") == 0) {
            error = home_get(client_socket, &parsed_http_request, thread_index);
            goto router_cleanup_parsed_request;
        }
    } else if (strcmp(parsed_http_request.url, "/sign-up") == 0) {
        if (strcmp(parsed_http_request.method, "GET") == 0) {
            error = sign_up_get(client_socket, &parsed_http_request, thread_index);
            goto router_cleanup_parsed_request;
        }
    } else if (strcmp(parsed_http_request.url, "/sign-up/create-user") == 0) {
        if (strcmp(parsed_http_request.method, "POST") == 0) {
            error = sign_up_create_user_post(client_socket, &parsed_http_request, thread_index);
            goto router_cleanup_parsed_request;
        }
    } else {
        error = not_found(client_socket, &parsed_http_request);
        goto router_cleanup_parsed_request;
    }

router_cleanup_parsed_request:
    http_request_free(&parsed_http_request);

router_cleanup_request:
    free(request);
    request = NULL;

router_exit:
    return error;
}

Error read_request(char **request_buffer, int client_socket) {
    Error error = {0};
    size_t buffer_size = 1024;

    *request_buffer = (char *)calloc(buffer_size + 1, sizeof(char));
    if (*request_buffer == NULL) {
        sprintf(error.message, "Failed to allocate memory for *request_buffer. Error code: %d", errno);
        error.panic = 1;
        return error;
    }

    (*request_buffer)[0] = '\0';

    size_t chunk_read = 0;
    int bytes_read;
    while ((bytes_read = recv(client_socket, (*request_buffer) + chunk_read, buffer_size - chunk_read, 0)) > 0) {
        chunk_read += bytes_read;

        if (chunk_read >= buffer_size) {
            buffer_size *= 2;
            *request_buffer = realloc((*request_buffer), buffer_size);
            if (*request_buffer == NULL) {
                free(*request_buffer);
                *request_buffer = NULL;
                sprintf(error.message, "Failed to reallocate memory for *request_buffer\nError code: %d", errno);
                error.panic = 1;
                return error;
            }
        } else {
            break;
        }
    }

    if (bytes_read == -1) {
        free(*request_buffer);
        *request_buffer = NULL;
        sprintf(error.message, "Failed extract headers from *request_buffer\nError code: %d", errno);
        error.panic = 1;
        return error;
    }

    (*request_buffer)[buffer_size] = '\0';

    return error;
}

Error parse_http_request(HttpRequest *parsed_http_request, const char *http_request) {
    Error error = {0};

    /** 1. Extract http request method */
    const char *method_end = strchr(http_request, ' ');
    size_t method_length = method_end - http_request;
    if (memcpy(parsed_http_request->method, http_request, method_length) == NULL) {
        sprintf(error.message, "Failed to copy method from http request into structure. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    parsed_http_request->method[method_length] = '\0';

    /** 2. Extract http request url and 3. url query params */
    const char *url_start = method_end + 1;
    const char *url_end;
    if ((url_end = strchr(url_start, ' ')) == NULL) {
        sprintf(error.message, "Failed to find char. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    const char *query_params_start = url_start;

    int query_params_start_index = -1; /** We start assuming there isn't any query params */
    /** Iterate until whitespace is found */
    while (!isspace((unsigned char)*query_params_start)) {
        /** If a '?' char is found along the way, that's the start of the query params */
        if (*query_params_start == '?') {
            query_params_start_index = query_params_start - http_request;
            break;
        }

        /** Keep moving forward */
        query_params_start++;
    }

    size_t query_params_length = 0;
    if (query_params_start_index >= 0) {
        query_params_length = url_end - (query_params_start + 1); /** Skip '?' char found at the beginning of query params */

        /**
         * Because we separate the url and url query params, we set
         * the end of the url to where the url query params start
         */
        url_end = &http_request[query_params_start_index];
    }

    size_t url_len = url_end - url_start;

    if (memcpy(parsed_http_request->url, url_start, url_len) == NULL) {
        sprintf(error.message, "Failed to copy url from http request into structure. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    parsed_http_request->url[url_len] = '\0';

    if (query_params_length > 0) {
        parsed_http_request->query_params = (char *)calloc(query_params_length + 1, sizeof(char));
        if (parsed_http_request->query_params == NULL) {
            sprintf(error.message, "Failed to allocate memory for parsed_http_request->query_params. Error code: %d", errno);
            error.panic = 1;
            http_request_free(parsed_http_request);
            return error;
        }

        /** (query_params_start + 1) -> skip '?' char found at the beginning of query params */
        if (memcpy(parsed_http_request->query_params, (query_params_start + 1), query_params_length) == NULL) {
            sprintf(error.message, "Failed to copy url query params from http request into structure. Error code: %d", errno);
            error.panic = 1;
            http_request_free(parsed_http_request);
            return error;
        }

        parsed_http_request->query_params[query_params_length] = '\0';
    }

    /** 4. Extract http version from request */
    char *http_version_start;
    if ((http_version_start = strchr(query_params_start, ' ')) == NULL) {
        sprintf(error.message, "Failed to find char. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    http_version_start++; /** Skip space */

    char *http_version_end;
    if ((http_version_end = strstr(http_version_start, "\r\n")) == NULL) {
        sprintf(error.message, "Failed to find string. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    size_t http_version_len = http_version_end - http_version_start;

    if (memcpy(parsed_http_request->http_version, http_version_start, http_version_len) == NULL) {
        sprintf(error.message, "Failed to copy http version from http request into structure. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    parsed_http_request->http_version[http_version_len] = '\0';

    /** 5. Extract http request headers */
    char *headers_start = http_version_end + 2; /** Skip "\r\n" */
    char *headers_end;
    if ((headers_end = strstr(headers_start, "\r\n\r\n")) == NULL) {
        sprintf(error.message, "Failed to find string. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    size_t headers_len = headers_end - headers_start;
    parsed_http_request->headers = (char *)calloc(headers_len + 1, sizeof(char));
    if (parsed_http_request->headers == NULL) {
        sprintf(error.message, "Failed to allocate memory for parsed_http_request->headers. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    if (memcpy(parsed_http_request->headers, headers_start, headers_len) == NULL) {
        sprintf(error.message, "Failed to copy headers from http request into structure. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    parsed_http_request->headers[headers_len] = '\0';

    /** 6. Extract http request body */
    char *body_start = headers_end + 4; /** Skip "\r\n\r\n" */
    char *body_end;
    if ((body_end = strchr(body_start, '\0')) == NULL) {
        sprintf(error.message, "Failed to find char. Error code: %d", errno);
        error.panic = 1;
        http_request_free(parsed_http_request);
        return error;
    }

    size_t body_length = body_end - body_start;
    if (body_length > 0) {
        parsed_http_request->body = (char *)calloc(body_length + 1, sizeof(char));
        if (parsed_http_request->body == NULL) {
            sprintf(error.message, "Failed to allocate memory for parsed_http_request->body. Error code: %d", errno);
            error.panic = 1;
            http_request_free(parsed_http_request);
            return error;
        }

        if (memcpy(parsed_http_request->body, body_start, body_length) == NULL) {
            sprintf(error.message, "Failed to copy request body from http request into structure. Error code: %d", errno);
            error.panic = 1;
            http_request_free(parsed_http_request);
            return error;
        }

        parsed_http_request->body[body_length] = '\0';
    }

    return error;
}

void http_request_free(HttpRequest *parsed_http_request) {
    free(parsed_http_request->query_params);
    parsed_http_request->query_params = NULL;

    free(parsed_http_request->body);
    parsed_http_request->body = NULL;

    free(parsed_http_request->headers);
    parsed_http_request->headers = NULL;
}

Error sign_up_create_user_post(int client_socket, HttpRequest *request, uint8_t thread_index) {
    Error error = {0};

    url_decode(&request->body);

    char email[255] = {0};
    parse_value(email, "email", request->body);

    char password[255] = {0};
    parse_value(password, "password", request->body);

    char repeat_password[255] = {0};
    parse_value(repeat_password, "repeat_password", request->body);

    char response[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

    if (send(client_socket, response, strlen(response), 0) == -1) {
        sprintf(error.message, "Failed send HTTP response. Error code: %d", errno);
        error.panic = PANIC;
        close(client_socket);
        return error;
    }

    close(client_socket);
    return error;
}

Error sign_up_get(int client_socket, HttpRequest *request, uint8_t thread_index) {
    Error error = {0};

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

    if (send(client_socket, response_headers, strlen(response_headers), 0) == -1) {
        sprintf(error.message, "Failed send HTTP response. Error code: %d", errno);
        error.panic = PANIC;
        close(client_socket);
        return error;
    }

    close(client_socket);
    return error;
}

Error home_get(int client_socket, HttpRequest *request, uint8_t thread_index) {
    Error error = {0};

    PGconn *conn = conn_pool[thread_index];

    const char query[] = "SELECT u.id, u.email, c.nicename AS country, CONCAT(ui.first_name, ' ', ui.last_name) AS full_name FROM app.users u JOIN app.users_info ui ON u.id = ui.user_id JOIN app.countries c ON ui.country_id = c.id";
    PGresult *users_result = PQexec(conn, query);

    if (PQresultStatus(users_result) != PGRES_TUPLES_OK) {
        sprintf(error.message, "%s\nError code: %d\n", PQerrorMessage(conn), errno);
        error.panic = PANIC;
        return error;
    }

    print_query_result(users_result);

    PQclear(users_result);

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

    if (send(client_socket, response_headers, strlen(response_headers), 0) == -1) {
        sprintf(error.message, "Failed send HTTP response. Error code: %d", errno);
        error.panic = PANIC;
        close(client_socket);
        return error;
    }

    close(client_socket);
    return error;
}

Error not_found(int client_socket, HttpRequest *request) {
    Error error = {0};

    char response[] = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
                      "<html><body><h1>404 Not Found</h1></body></html>";

    if (send(client_socket, response, strlen(response), 0) == -1) {
        sprintf(error.message, "Failed send HTTP response. Error code: %d", errno);
        error.panic = PANIC;
        close(client_socket);
        return error;
    }

    close(client_socket);
    return error;
}

Error url_decode(char **string) {
    Error error = {0};

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

    return error;
}

Error parse_value(char buffer[], const char key_name[], char *string) {
    Error error = {0};

    /** To avoid modifying the original string pointer, create a new one that can be freely modified */
    char *key = string;

    while (*key != '\0') {
        char *key_end = strchr(key, '=');
        size_t key_length = key_end - key;

        char *value_start = key_end + 1;
        char *value_end = strchr(value_start, '&');
        if (value_end == NULL) {
            value_end = strchr(value_start, '\0');
        }

        size_t value_length = value_end - value_start;

        if (strncmp(key, key_name, key_length) == 0) {
            memcpy(buffer, value_start, value_length);
            buffer[value_length] = '\0';
        }

        if (*value_end == '\0') {
            break;
        }

        key = value_end + 1;
    }

    if (buffer == NULL) {
        sprintf(error.message, "Value not found per key. Error code: %d", errno);
        error.panic = PANIC;
        return error;
    }

    return error;
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
 * @brief      Read values from a file into a structure. Ignores lines that start with '#' (comments).
 *             The values in the file must adhere to the following rules:
 *                  1. Each value must be on a new line.
 *                  2. Values must adhere to the specified order and length defined in the structure
 *                     they are loaded into.
 *                  3. values must start inmediately after the equal sign and be contiguous.
 *                     e.g. =helloworld
 *
 * @param[out] structure A structure with fixed-size string fields for each value in the file.
 * @param      project_root_path The path to project root.
 * @param      file_path_relative_to_project_root The path to the file from project root.
 * @return     Error information if an error occurs.
 */
Error load_values_from_file(void *structure, const char *project_root_path, const char *file_path_relative_to_project_root) {
    Error error = {0};

    char file_absolute_path[MAX_ABSOLUTE_PATH_LENGTH];
    if (sprintf(file_absolute_path, "%s/%s", project_root_path, file_path_relative_to_project_root) < 0) {
        sprintf(error.message, "Absolute path truncated. Error code: %d", errno);
        error.panic = 1;
        return error;
    }

    FILE *file = fopen(file_absolute_path, "r");

    if (file == NULL) {
        sprintf(error.message, "Failed to open file. Error code: %d", errno);
        error.panic = 1;
        return error;
    }

    char line[MAX_LINE_LENGTH];

    size_t structure_element_offset = 0;

    unsigned int read_values_count = 0;

    while (fgets(line, MAX_LINE_LENGTH, file) != NULL) {
        /** Does line have a comment? */
        char *hash_position = strchr(line, '#');
        if (hash_position != NULL) {
            /** We don't care about comments. Truncate line at the start of a comment */
            *hash_position = '\0';
        }

        /** The value we want to read starts after an '=' sign */
        char *equal_sign = strchr(line, '=');
        if (equal_sign == NULL) {
            /** This line does not contain a value, continue to next line */
            continue;
        }

        equal_sign++; /** Move the pointer past the '=' character to the beginning of the value */

        size_t value_char_index = 0;

        /** Extract 'value characters' until a 'whitespace' character or null-terminator is encountered */
        while (*equal_sign != '\0' && !isspace((unsigned char)*equal_sign)) {
            ((char *)structure)[structure_element_offset + value_char_index] = *equal_sign;
            value_char_index++;
            equal_sign++;
        }

        ((char *)structure)[structure_element_offset + value_char_index] = '\0';

        /** Next element in the structure should start after the read value null-terminator */
        structure_element_offset += value_char_index + 1;
        read_values_count++;
    }

    fclose(file);
    return error;
}

/** TODO: Check for all possible errors inside get_html_files_paths */
Error get_html_files_paths(char **html_files_paths, const char *base_path, uint8_t level, uint8_t *total_html_files) {
    Error error = {0};

    DIR *dir = opendir(base_path);
    if (dir == NULL) {
        sprintf(error.message, "Failed to open directory %s. Error code: %d", base_path, errno);
        error.panic = 1;
        return error;
    }

    struct dirent *entry;
    char path[MAX_PATH_LENGTH];
    struct stat statbuf;
    size_t entry_name_length;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            sprintf(path, "%s/%s", base_path, entry->d_name);

            if (stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
                if ((error = get_html_files_paths(html_files_paths, path, level + 1, total_html_files)).panic) {
                    error.panic = 1;
                    return error;
                }
            } else {
                entry_name_length = strlen(entry->d_name);
                if (entry_name_length > 5 && strcmp(entry->d_name + entry_name_length - 5, ".html") == 0) {
                    if (*total_html_files < MAX_HTML_FILES) {
                        strcpy(html_files_paths[*total_html_files], path);
                        (*total_html_files)++;
                    } else {
                        closedir(dir);
                        sprintf(error.message, "MAX_HTML_FILES(%d) limit reached. Error code: %d", MAX_HTML_FILES, errno);
                        error.panic = 1;
                        return error;
                    }
                }
            }
        }
    }

    closedir(dir);
    return error;
}

void free_html_files_paths(char **html_files_paths) {
    uint8_t i;
    for (i = 0; i < MAX_HTML_FILES; i++) {
        memset(html_files_paths[i], 0, MAX_PATH_LENGTH);
        free(html_files_paths[i]);
        html_files_paths[i] = NULL;
    }

    free(html_files_paths);
    html_files_paths = NULL;
}

Error calculate_file_size(long *file_size, char *absolute_file_path) {
    Error error = {0};

    FILE *file = fopen(absolute_file_path, "r");

    if (file == NULL) {
        sprintf(error.message, "Failed to open file. Error code: %d", errno);
        error.panic = PANIC;
        return error;
    }

    if (fseek(file, 0, SEEK_END) == -1) {
        fclose(file);
        sprintf(error.message, "Failed to move the 'file position indicator' to the end of the file. Error code: %d", errno);
        error.panic = PANIC;
        return error;
    }

    *file_size = ftell(file);
    if (*file_size == -1) {
        fclose(file);
        sprintf(error.message, "Failed to determine the current 'file position indicator' of the file. Error code: %d", errno);
        error.panic = PANIC;
        return error;
    }

    rewind(file);
    fclose(file);

    return error;
}

Error read_file(char **buffer, char *absolute_file_path, size_t file_size) {
    Error error = {0};

    FILE *file = fopen(absolute_file_path, "r");

    if (file == NULL) {
        sprintf(error.message, "Failed to open file. Error code: %d", errno);
        error.panic = PANIC;
        return error;
    }

    if (fread(*buffer, sizeof(char), file_size, file) != file_size) {
        if (feof(file)) {
            sprintf(error.message, "End of file reached before reading all elements. Error code: %d", errno);
        }

        if (ferror(file)) {
            sprintf(error.message, "An error occurred during the fread operation. Error code: %d", errno);
        }

        fclose(file);

        error.panic = PANIC;
        return error;
    }

    fclose(file);

    return error;
}

void print_query_result(PGresult *query_result) {
    const int num_columns = PQnfields(query_result);
    const int num_rows = PQntuples(query_result);

    int col = 0;
    int row = 0;
    int i = 0;

    for (col = 0; col < num_columns; col++) {
        printf("| %-48s ", PQfname(query_result, col));
    }
    printf("|\n");

    printf("|");
    for (col = 0; col < num_columns; col++) {
        for (i = 0; i < 50; i++) {
            printf("-");
        }
        printf("|");
    }
    printf("\n");

    for (row = 0; row < num_rows; row++) {
        for (col = 0; col < num_columns; col++) {
            printf("| %-48s ", PQgetvalue(query_result, row, col));
        }
        printf("|\n");
    }

    printf("\n");
}

void enqueue_client_socket(int *client_socket) {
    ClientSocketQueueNode *new_node = malloc(sizeof(ClientSocketQueueNode));
    new_node->client_socket = client_socket;
    new_node->next = NULL;

    if (tail_client_socket_queue == NULL) {
        head_client_socket_queue = new_node;
    } else {
        tail_client_socket_queue->next = new_node;
    }

    tail_client_socket_queue = new_node;
}

void *dequeue_client_socket() {
    if (head_client_socket_queue == NULL) {
        return NULL;
    }

    int *result = head_client_socket_queue->client_socket;
    ClientSocketQueueNode *temp = head_client_socket_queue;
    head_client_socket_queue = head_client_socket_queue->next;

    if (head_client_socket_queue == NULL) {
        tail_client_socket_queue = NULL;
    }

    free(temp);
    temp = NULL;

    return result;
}

void sigint_handler(int signo) {
    if (signo == SIGINT) {
        printf("\nReceived SIGINT, exiting program...\n");
        keep_running = 0;
    }
}
