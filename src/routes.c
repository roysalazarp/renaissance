#include "headers.h"

void router(RequestCtx request_ctx) {
    Arena *scratch_arena = request_ctx.scratch_arena;
    int client_socket = request_ctx.client_socket;

    char *request = (char *)scratch_arena->current;
    request_ctx.request = request;

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
            printf("fd %d - Empty request\n", client_socket);
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

    scratch_arena->current = tmp_request;

    String url = find_http_request_value("URL", request);

    if (strncmp(url.start_addr, URL("/.well-known/assetlinks.json"), strlen(URL("/.well-known/assetlinks.json"))) == 0 && strncmp(method.start_addr, "GET", method.length) == 0) {
        char buff[] = "/public/.well-known/assetlinks.json";
        String new_url = {0};
        new_url.start_addr = buff;
        new_url.length = strlen(buff);

        public_get(request_ctx, new_url);
        return;
    }

    if (strncmp(url.start_addr, "/public", strlen("/public")) == 0 && strncmp(method.start_addr, "GET", method.length) == 0) {
        public_get(request_ctx, url);
        return;
    }

    if (strncmp(url.start_addr, URL("/"), strlen(URL("/"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            home_get(request_ctx);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/test"), strlen(URL("/test"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            test_get(request_ctx);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/login"), strlen(URL("/login"))) == 0 || strncmp(url.start_addr, URL_WITH_QUERY("/login"), strlen(URL_WITH_QUERY("/login"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            view_get(request_ctx, "login", true);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/login/create-session"), strlen(URL("/login/create-session"))) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            login_create_session_post(request_ctx);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/register"), strlen(URL("/register"))) == 0 || strncmp(url.start_addr, URL_WITH_QUERY("/register"), strlen(URL_WITH_QUERY("/register"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            view_get(request_ctx, "register", true);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/register/create-account"), strlen(URL("/register/create-account"))) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            register_create_account_post(request_ctx);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/auth"), strlen(URL("/auth"))) == 0 || strncmp(url.start_addr, URL_WITH_QUERY("/auth"), strlen(URL_WITH_QUERY("/auth"))) == 0) {
        if (strncmp(method.start_addr, "GET", method.length) == 0) {
            view_get(request_ctx, "auth", true);
            return;
        }
    }

    if (strncmp(url.start_addr, URL("/auth/validate-email"), strlen(URL("/auth/validate-email"))) == 0) {
        if (strncmp(method.start_addr, "POST", method.length) == 0) {
            auth_validate_email_post(request_ctx);
            return;
        }
    }

    view_get(request_ctx, "not_found", false);

    return;
}

void public_get(RequestCtx request_ctx, String url) {
    Arena *scratch_arena = request_ctx.scratch_arena;
    int client_socket = request_ctx.client_socket;

    char *path = (char *)arena_alloc(scratch_arena, sizeof('.') + url.length);
    char *tmp_path = path;
    *tmp_path = '.';
    tmp_path++;
    strncpy(tmp_path, url.start_addr, url.length);

    char *public_file_type = file_content_type(scratch_arena, path);
    char *content = find_value(path, arena_data->public_files_dict);

    char *response = (char *)scratch_arena->current;

    sprintf(response,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n\r\n"
            "%s",
            public_file_type, content);

    char *response_end = response;
    while (*response_end != '\0') {
        response_end++;
    }

    scratch_arena->current = response_end + 1;

    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);

    arena_free(scratch_arena);
}

/**
 * Generic handler for pages (e.g., login, registration) that do not require
 * authentication. when `accepts_query_params` is true, query values are
 * rendered in their respective template placeholders.
 */
void view_get(RequestCtx request_ctx, char *view, boolean accepts_query_params) {
    Arena *scratch_arena = request_ctx.scratch_arena;
    int client_socket = request_ctx.client_socket;
    char *request = request_ctx.request;

    Dict replaces = {0};
    if (accepts_query_params) {
        String query_params = find_http_request_value("QUERY_PARAMS", request);

        if (query_params.length > 0) {
            replaces = parse_and_decode_params(scratch_arena, query_params);
        }
    }

    char *template = find_value(view, arena_data->templates);

    if (replaces.start_addr) {
        char *template_cpy = (char *)scratch_arena->current;
        memcpy(template_cpy, template, strlen(template) + 1);

        char *ptr = replaces.start_addr;
        while (ptr < replaces.end_addr) {
            char *key = ptr;
            char *value = ptr + strlen(ptr) + 1;

            replace_val(template_cpy, key, value);

            ptr += strlen(ptr) + 1; /* pass key */
            ptr += strlen(ptr) + 1; /* pass value */
        }

        scratch_arena->current = (char *)scratch_arena->current + strlen(template_cpy) + 1;

        /** Re-set template to point to "rendered template copy" */
        template = template_cpy;
    }

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    size_t response_length = strlen(response_headers) + strlen(template);

    char *response = (char *)arena_alloc(scratch_arena, response_length + 1);

    sprintf(response, "%s%s", response_headers, template);
    response[response_length] = '\0';

    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);

    arena_free(scratch_arena);
}

/**
 * A dummy page used for testing purposes.
 */
void test_get(RequestCtx request_ctx) {
    Arena *scratch_arena = request_ctx.scratch_arena;
    int client_socket = request_ctx.client_socket;
    char *request = request_ctx.request;

    DBConnection *connection = get_available_connection(scratch_arena);

    const char *command_1 = "SELECT * FROM app.countries WHERE id = $1 OR id = $2";
    Oid paramTypes_1[2] = {23, 23};
    int id1 = htonl(3);
    int id2 = htonl(23);
    const char *paramValues_1[2];
    paramValues_1[0] = (char *)&id1;
    paramValues_1[1] = (char *)&id2;
    int paramLengths_1[2] = {sizeof(id1), sizeof(id2)};
    int paramFormats_1[2] = {1, 1};

    PGresult *result_1 = WPQsendQueryParams(connection, command_1, N2_PARAMS, paramTypes_1, paramValues_1, paramLengths_1, paramFormats_1, TEXT);

    print_query_result(result_1);

    PQclear(result_1);

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *template = find_value("test", arena_data->templates);

    char *template_cpy = (char *)scratch_arena->current;

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

    scratch_arena->current = (char *)scratch_arena->current + strlen(template_cpy) + 1;

    size_t response_length = strlen(response_headers) + strlen(template_cpy);

    char *response = (char *)arena_alloc(scratch_arena, response_length + 1);

    sprintf(response, "%s%s", response_headers, template_cpy);
    response[response_length] = '\0';

    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);

    release_request_resources_and_exit(scratch_arena, connection);
}

void home_get(RequestCtx request_ctx) {
    Arena *scratch_arena = request_ctx.scratch_arena;
    int client_socket = request_ctx.client_socket;
    char *request = request_ctx.request;

    DBConnection *connection = get_available_connection(scratch_arena);

    char *template = find_value("home", arena_data->templates);

    char *response = NULL;

    Dict user = is_authenticated(request_ctx, connection);
    if (user.start_addr) {
        char *template_cpy = (char *)scratch_arena->current;

        memcpy(template_cpy, template, strlen(template) + 1);

        render_val(template_cpy, "authenticated", "Account");
        replace_val(template_cpy, "authenticated_redirect", "/account");

        scratch_arena->current = (char *)scratch_arena->current + strlen(template_cpy) + 1;

        char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        size_t response_length = strlen(response_headers) + strlen(template_cpy);

        response = (char *)arena_alloc(scratch_arena, response_length + 1);

        sprintf(response, "%s%s", response_headers, template_cpy);
        response[response_length] = '\0';

        goto send_response;
    }

    char *template_cpy = (char *)scratch_arena->current;

    memcpy(template_cpy, template, strlen(template) + 1);

    render_val(template_cpy, "authenticated", "Login");
    replace_val(template_cpy, "authenticated_redirect", "/auth");

    scratch_arena->current = (char *)scratch_arena->current + strlen(template_cpy) + 1;

    char response_headers[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    size_t response_length = strlen(response_headers) + strlen(template_cpy);

    response = (char *)arena_alloc(scratch_arena, response_length + 1);

    sprintf(response, "%s%s", response_headers, template_cpy);
    response[response_length] = '\0';

send_response:
    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);

    release_request_resources_and_exit(scratch_arena, connection);
}

void auth_validate_email_post(RequestCtx request_ctx) {
    Arena *scratch_arena = request_ctx.scratch_arena;
    int client_socket = request_ctx.client_socket;
    char *request = request_ctx.request;

    DBConnection *connection = get_available_connection(scratch_arena);

    String body = find_body(request);
    Dict params = parse_and_decode_params(scratch_arena, body);

    char *email = find_value("email", params);

    const char *command_1 = "SELECT email FROM app.users WHERE email = $1";
    Oid paramTypes_1[1] = {25};
    const char *paramValues_1[1];
    paramValues_1[0] = email;
    int paramLengths_1[1] = {0};
    int paramFormats_1[1] = {0};

    PGresult *result_1 = WPQsendQueryParams(connection, command_1, N1_PARAMS, paramTypes_1, paramValues_1, paramLengths_1, paramFormats_1, TEXT);

    print_query_result(result_1);

    int rows = PQntuples(result_1);

    print_query_result(result_1);
    PQclear(result_1);

    char *response_headers[200];
    memset(response_headers, 0, sizeof(response_headers));

    String encoded_email = find_body_value("email", body);

    if (rows > 0) {
        sprintf((char *)response_headers, "HTTP/1.1 200 OK\r\nHX-Redirect: /login?email=%.*s\r\n\r\n", (int)encoded_email.length, encoded_email.start_addr);
    } else {
        sprintf((char *)response_headers, "HTTP/1.1 200 OK\r\nHX-Redirect: /register?email=%.*s\r\n\r\n", (int)encoded_email.length, encoded_email.start_addr);
    }

    if (send(client_socket, response_headers, strlen((char *)response_headers), 0) == -1) {
    }

    close(client_socket);

    release_request_resources_and_exit(scratch_arena, connection);
}

void register_create_account_post(RequestCtx request_ctx) {
    Arena *scratch_arena = request_ctx.scratch_arena;
    int client_socket = request_ctx.client_socket;
    char *request = request_ctx.request;

    DBConnection *connection = get_available_connection(scratch_arena);

    String body = find_body(request);
    Dict params = parse_and_decode_params(scratch_arena, body);

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

    const char *command_1 = "INSERT INTO app.users (email, password) VALUES ($1, $2)";
    Oid paramTypes_1[2] = {25, 25};
    const char *paramValues_1[2];
    paramValues_1[0] = email;
    paramValues_1[1] = secure_password;
    int paramLengths_1[2] = {0, 0};
    int paramFormats_1[2] = {0, 0};

    PGresult *result_1 = WPQsendQueryParams(connection, command_1, N2_PARAMS, paramTypes_1, paramValues_1, paramLengths_1, paramFormats_1, TEXT);

    print_query_result(result_1);

    PQclear(result_1);

    char response_headers[] = "HTTP/1.1 200 OK\r\nHX-Redirect: /\r\n\r\n";

    if (send(client_socket, response_headers, strlen((char *)response_headers), 0) == -1) {
    }

    close(client_socket);

    release_request_resources_and_exit(scratch_arena, connection);
}

void login_create_session_post(RequestCtx request_ctx) {
    Arena *scratch_arena = request_ctx.scratch_arena;
    int client_socket = request_ctx.client_socket;
    char *request = request_ctx.request;

    DBConnection *connection = get_available_connection(scratch_arena);

    String body = find_body(request);
    Dict params = parse_and_decode_params(scratch_arena, body);

    char *email = find_value("email", params);

    const char *command_1 = "SELECT id, password FROM app.users WHERE email = $1";
    Oid paramTypes_1[N1_PARAMS] = {25};
    const char *paramValues_1[N1_PARAMS];
    paramValues_1[0] = email;
    int paramLengths_1[N1_PARAMS] = {0};
    int paramFormats_1[N1_PARAMS] = {0};

    PGresult *result_1 = WPQsendQueryParams(connection, command_1, N1_PARAMS, paramTypes_1, paramValues_1, paramLengths_1, paramFormats_1, BINARY);

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

    PGresult *result_2 = WPQsendQueryParams(connection, command_2, N1_PARAMS, paramTypes_2, paramValues_2, paramLengths_2, paramFormats_2, TEXT);

    PQclear(result_1);
    print_query_result(result_2);

    char *response = (char *)scratch_arena->current;

    char *session_id = PQgetvalue(result_2, 0, 0);
    char *expires_at = PQgetvalue(result_2, 0, 1);

    sprintf(response,
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session_id=%s; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=%s\r\n"
            "HX-Redirect: /\r\n\r\n",
            session_id, expires_at);

    PQclear(result_2);

    scratch_arena->current = response + strlen(response) + 1;

    if (send(client_socket, response, strlen(response), 0) == -1) {
    }

    close(client_socket);

    release_request_resources_and_exit(scratch_arena, connection);
}

Dict is_authenticated(RequestCtx request_ctx, DBConnection *connection) {
    Arena *scratch_arena = request_ctx.scratch_arena;
    char *request = request_ctx.request;

    Dict user = {0};

    String cookie = find_http_request_value("Cookie", request);
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

            PGresult *result_1 = WPQsendQueryParams(connection, command_1, N1_PARAMS, paramTypes_1, paramValues_1, paramLengths_1, paramFormats_1, TEXT);

            int num_rows = PQntuples(result_1);
            if (num_rows) {
                print_query_result(result_1);

                char *user_info = (char *)scratch_arena->current;
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

                scratch_arena->current = tmp_user_info + 1;

                PQclear(result_1);

                return user;
            }
        }
    }

    return user;
}

void release_request_resources_and_exit(Arena *scratch_arena, DBConnection *connection) {
    uint8_t was_request_queued = connection->client.queued;

    /* Set connection as unused */
    memset(&(connection->client), 0, sizeof(Client));

    /** Set connection available for write */
    int conn_socket = PQsocket(connection->conn);
    event.events = EPOLLOUT | EPOLLET;
    event.data.ptr = connection;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_socket, &event);

    arena_free(scratch_arena);

    if (was_request_queued) {
        longjmp(db_ctx, 1);
    }

    longjmp(ctx, 1);
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

/** RE-DO */
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

/** RE-DO */
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

/** RE-DO */
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
