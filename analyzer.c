#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define MAX_PROCESSES 2048
#define MAX_EVENTS 20000
#define MAX_LINE 8192
#define FIELD_SIZE 2048
#define SMALL_FIELD 128
#define PREFIX_SIZE 8192

typedef struct {
    int pid;
    int ppid;
    int event_count;
} Process;

typedef struct {
    int pid;
    int ppid;
    char intent[64];
    char path[FIELD_SIZE];
    char action[64];
    char protocol[SMALL_FIELD];
    char dest_ip[SMALL_FIELD];
    int dest_port;
    long long payload_bytes;
    int has_port;
    int has_payload;
    int is_network;
} Event;

static Process processes[MAX_PROCESSES];
static Event events[MAX_EVENTS];

static int process_count = 0;
static int event_count = 0;

static int total = 0;
static int valid = 0;
static int malformed = 0;
static int reads = 0;
static int writes = 0;
static int deletes = 0;
static int clones = 0;
static int allowed = 0;
static int denied = 0;
static int errors = 0;
static int socket_events = 0;
static int connect_events = 0;
static int transmit_events = 0;
static int other_network_events = 0;

static int find_process(int pid) {
    for (int i = 0; i < process_count; i++) {
        if (processes[i].pid == pid)
            return i;
    }
    return -1;
}

static void copy_field(char *dst, size_t dst_size, const char *src,
                       const char *fallback) {
    snprintf(dst, dst_size, "%s", src ? src : fallback);
}

static void record_event(const Event *source) {
    int index = find_process(source->pid);

    if (index < 0) {
        if (process_count >= MAX_PROCESSES)
            return;

        index = process_count++;
        processes[index].pid = source->pid;
        processes[index].ppid = source->ppid;
        processes[index].event_count = 0;
    }

    processes[index].event_count++;

    if (processes[index].ppid <= 0 && source->ppid > 0)
        processes[index].ppid = source->ppid;

    if (event_count >= MAX_EVENTS)
        return;

    events[event_count++] = *source;
}

/* Hide only routine library FILE_READ events from the detailed display. */
static int is_noise_event(const Event *e) {
    if (strcmp(e->intent, "FILE_READ") != 0)
        return 0;

    const char *prefixes[] = { "/usr/lib", "/lib" };

    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t len = strlen(prefixes[i]);
        if (strncmp(e->path, prefixes[i], len) == 0 &&
            (e->path[len] == '/' || e->path[len] == '\0'))
            return 1;
    }

    return 0;
}

static int is_visited(int pid, const int visited[], int visited_count) {
    for (int i = 0; i < visited_count; i++) {
        if (visited[i] == pid)
            return 1;
    }
    return 0;
}

static int count_children(int pid, const int visited[], int visited_count) {
    int count = 0;
    for (int i = 0; i < process_count; i++) {
        if (processes[i].ppid == pid &&
            processes[i].pid != pid &&
            !is_visited(processes[i].pid, visited, visited_count))
            count++;
    }
    return count;
}

static void print_tree(int pid, const char *prefix, int is_last,
                       int is_root, int visited[], int *visited_count) {
    if (is_visited(pid, visited, *visited_count) ||
        *visited_count >= MAX_PROCESSES)
        return;

    int index = find_process(pid);
    if (index < 0)
        return;

    visited[(*visited_count)++] = pid;

    printf("%s", prefix);
    if (!is_root)
        printf("%s", is_last ? "└── " : "├── ");

    printf("PID: %d (PPID: %d, Events: %d)\n",
           processes[index].pid, processes[index].ppid,
           processes[index].event_count);

    int child_count = count_children(pid, visited, *visited_count);
    int child_number = 0;

    for (int i = 0; i < process_count; i++) {
        int child_pid = processes[i].pid;
        if (processes[i].ppid != pid || child_pid == pid ||
            is_visited(child_pid, visited, *visited_count))
            continue;

        child_number++;
        char child_prefix[PREFIX_SIZE];
        snprintf(child_prefix, sizeof(child_prefix), "%s%s", prefix,
                 is_root ? "" : (is_last ? "    " : "│   "));

        print_tree(child_pid, child_prefix, child_number == child_count,
                   0, visited, visited_count);
    }
}

static void print_activities(void) {
    printf("\n========== PROCESS ACTIVITIES ==========\n");

    for (int p = 0; p < process_count; p++) {
        int visible = 0;

        for (int e = 0; e < event_count; e++) {
            if (events[e].pid == processes[p].pid &&
                !is_noise_event(&events[e])) {
                visible++;
            }
        }
        if (visible == 0)
            continue;

        printf("\nPID: %d\n", processes[p].pid);

        for (int e = 0; e < event_count; e++) {
            const Event *ev = &events[e];
            if (ev->pid != processes[p].pid || is_noise_event(ev))
                continue;

            if (ev->is_network) {
                printf("  %-16s | %-7s | ",
                       ev->intent, ev->action);
                if (ev->protocol[0])
                    printf("protocol=%s ", ev->protocol);
                if (ev->dest_ip[0])
                    printf("destination=%s ", ev->dest_ip);
                if (ev->has_port)
                    printf("port=%d ", ev->dest_port);
                if (ev->has_payload)
                    printf("payload_bytes=%lld ", ev->payload_bytes);
                printf("\n");
            } else {
                printf("  %-16s | %-7s | %s\n",
                       ev->intent, ev->action, ev->path);
            }
        }
    }
}

static const char *get_string(struct json_object *obj, const char *key) {
    struct json_object *field;
    if (json_object_object_get_ex(obj, key, &field) &&
        json_object_is_type(field, json_type_string))
        return json_object_get_string(field);
    return NULL;
}

static int get_int(struct json_object *obj, const char *key, int fallback) {
    struct json_object *field;
    if (json_object_object_get_ex(obj, key, &field))
        return json_object_get_int(field);
    return fallback;
}

int main(int argc, char *argv[]) {
    const char *filename = argc > 1 ? argv[1] : "depsandbox.log";
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Unable to open log file");
        return 1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), file)) {
        /* Skip plain-text supervisor status messages. */
        if (line[0] != '{')
            continue;

        total++;
        struct json_object *obj = json_tokener_parse(line);
        if (!obj || !json_object_is_type(obj, json_type_object)) {
            malformed++;
            if (obj)
                json_object_put(obj);
            continue;
        }

        Event ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = get_int(obj, "pid", 0);
        ev.ppid = get_int(obj, "ppid", 0);

        const char *intent = get_string(obj, "intent");
        const char *event_name = get_string(obj, "event");
        const char *path = get_string(obj, "path");
        const char *action = get_string(obj, "action");
        const char *protocol = get_string(obj, "protocol");
        const char *dest_ip = get_string(obj, "dest_ip");

        if (ev.pid <= 0 || (!intent && !event_name)) {
            malformed++;
            json_object_put(obj);
            continue;
        }

        if (intent) {
            copy_field(ev.intent, sizeof(ev.intent), intent, "UNKNOWN");
            copy_field(ev.path, sizeof(ev.path), path, "(no path recorded)");
            copy_field(ev.action, sizeof(ev.action), action, "UNKNOWN");

            if (strcmp(intent, "FILE_READ") == 0)
                reads++;
            else if (strcmp(intent, "FILE_WRITE") == 0)
                writes++;
            else if (strcmp(intent, "FILE_DELETE") == 0)
                deletes++;
            else if (strcmp(intent, "CLONE") == 0)
                clones++;
        } else {
            ev.is_network = 1;
            copy_field(ev.intent, sizeof(ev.intent), event_name, "NETWORK_EVENT");
            copy_field(ev.path, sizeof(ev.path), "", "");
            copy_field(ev.action, sizeof(ev.action), action, "OBSERVED");
            copy_field(ev.protocol, sizeof(ev.protocol), protocol, "");
            copy_field(ev.dest_ip, sizeof(ev.dest_ip), dest_ip, "");
            ev.dest_port = get_int(obj, "dest_port", 0);
            ev.has_port = ev.dest_port > 0;

            struct json_object *payload_field;
            if (json_object_object_get_ex(obj, "payload_bytes", &payload_field)) {
                ev.payload_bytes = json_object_get_int64(payload_field);
                ev.has_payload = 1;
            }

            if (strcmp(event_name, "SOCKET_CREATE") == 0)
                socket_events++;
            else if (strcmp(event_name, "CONNECT") == 0)
                connect_events++;
            else if (strcmp(event_name, "DATA_TRANSMIT") == 0)
                transmit_events++;
            else
                other_network_events++;
        }

        if (action && strcmp(action, "ALLOW") == 0)
            allowed++;
        else if (action && strcmp(action, "DENY") == 0)
            denied++;
        else if (action && strcmp(action, "ERROR") == 0)
            errors++;

        valid++;
        record_event(&ev);
        json_object_put(obj);
    }

    fclose(file);

    printf("\n========== DEPSANDBOX SECURITY REPORT ==========\n");
    printf("Log file             : %s\n", filename);
    printf("Event records        : %d\n", total);
    printf("Valid events         : %d\n", valid);
    printf("Malformed events     : %d\n", malformed);

    printf("\n[FILE / PROCESS OPERATIONS]\n");
    printf("File read requests   : %d\n", reads);
    printf("File write requests  : %d\n", writes);
    printf("Delete attempts      : %d\n", deletes);
    printf("Process creation     : %d\n", clones);

    printf("\n[NETWORK EVENTS]\n");
    printf("Socket creation     : %d\n", socket_events);
    printf("Connection attempts : %d\n", connect_events);
    printf("Data transmit events: %d\n", transmit_events);
    printf("Other network events: %d\n", other_network_events);

    printf("\n[RECORDED ACTIONS]\n");
    printf("ALLOW                : %d\n", allowed);
    printf("DENY                 : %d\n", denied);
    printf("ERROR                : %d\n", errors);

    printf("\n[PROCESS SUMMARY]\n");
    printf("Unique PIDs observed : %d\n", process_count);

    printf("\n========== PROCESS TREE ==========\n");
    int visited[MAX_PROCESSES];
    int visited_count = 0;

    for (int i = 0; i < process_count; i++) {
        if (find_process(processes[i].ppid) < 0 &&
            !is_visited(processes[i].pid, visited, visited_count)) {
            print_tree(processes[i].pid, "", 1, 1,
                       visited, &visited_count);
        }
    }

    for (int i = 0; i < process_count; i++) {
        if (!is_visited(processes[i].pid, visited, visited_count)) {
            printf("\n[Unconnected process records]\n");
            print_tree(processes[i].pid, "", 1, 1,
                       visited, &visited_count);
        }
    }

    printf("==================================\n");
    print_activities();
    return 0;
}
