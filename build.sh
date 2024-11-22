mkdir -p ./build

gcc \
    -std=c89 \
    -g \
    -Wall \
    -Wextra \
    -Werror \
    -pedantic \
    -Wno-unused-variable \
    -Wno-unused-parameter \
    -Wno-declaration-after-statement \
    -Wno-overlength-strings \
    -Wno-format-overflow \
    -Wno-error=unused-but-set-variable \
    -Wno-error=discarded-qualifiers \
    -o \
    ./build/main \
    main.c \
    -I/workspaces/postgresql-16.0/src/interfaces/libpq \
    -I/workspaces/postgresql-16.0/src/include \
    -L/workspaces/postgresql-16.0/pgsql/lib \
    -lpq \
    -I/workspaces/phc-winner-argon2/include \
    -L/workspaces/phc-winner-argon2 \
    -largon2 \
    -pthread # Required by largon2
