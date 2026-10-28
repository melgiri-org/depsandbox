
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define MAX_PROCESSES 2048
#define MAX_EVENTS 20000
#define MAX_LINE 8192
#define FIELD_SIZE 2048
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

static int find_process(int pid) {
    for (int i = 0; i < process_count; i++) {
        if (processes[i].pid == pid)
            return i;
    }
    return -1;
}

static void record_event(int pid, int ppid,
                         const char *intent,
                         const char *path,
                         const char *action) {
    int index = find_process(pid);

    if (index < 0) {
        if (process_count >= MAX_PROCESSES)
            return;

        index = process_count++;
        processes[index].pid = pid;
        processes[index].ppid = ppid;
        processes[index].event_count = 0;
    }

    processes[index].event_count++;

    if (processes[index].ppid <= 0 && ppid > 0)
        processes[index].ppid = ppid;

    if (event_count >= MAX_EVENTS)
        return;

    Event *e = &events[event_count++];

    e->pid = pid;
    e->ppid = ppid;

    snprintf(e->intent, sizeof(e->intent), "%s",
             intent ? intent : "UNKNOWN");

    snprintf(e->path, sizeof(e->path), "%s",
             path ? path : "(no path recorded)");

    snprintf(e->action, sizeof(e->action), "%s",
             action ? action : "UNKNOWN");
}

static int is_visited(int pid, const int visited[],
                      int visited_count) {
    for (int i = 0; i < visited_count; i++) {
        if (visited[i] == pid)
            return 1;
    }
    return 0;
}

static int count_children(int pid, const int visited[],
                          int visited_count) {
    int count = 0;

    for (int i = 0; i < process_count; i++) {
        if (processes[i].ppid == pid &&
            processes[i].pid != pid &&
            !is_visited(processes[i].pid,
                        visited, visited_count)) {
            count++;
        }
    }
    return count;
}

/*
 * Print only the process hierarchy.
 * prefix preserves vertical lines from ancestor branches.
 */
static void print_tree(int pid, const char *prefix,
                       int is_last, int is_root,
                       int visited[], int *visited_count) {
    if (is_visited(pid, visited, *visited_count))
        return;

    if (*visited_count >= MAX_PROCESSES)
        return;

    int index = find_process(pid);
    if (index < 0)
        return;

    visited[(*visited_count)++] = pid;

    printf("%s", prefix);

    if (!is_root)
        printf("%s", is_last ? "└── " : "├── ");

    printf("PID: %d (PPID: %d, Events: %d)\n",
           processes[index].pid,
           processes[index].ppid,
           processes[index].event_count);

    int child_count = count_children(
        pid, visited, *visited_count);
    int child_number = 0;

    for (int i = 0; i < process_count; i++) {
        int child_pid = processes[i].pid;

        if (processes[i].ppid != pid ||
            child_pid == pid ||
            is_visited(child_pid, visited, *visited_count))
            continue;

        child_number++;

        char child_prefix[PREFIX_SIZE];

        snprintf(child_prefix, sizeof(child_prefix),
                 "%s%s",
                 prefix,
                 is_root ? "" : (is_last ? "    " : "│   "));

        print_tree(child_pid, child_prefix,
                   child_number == child_count,
                   0, visited, visited_count);
    }
}

static void print_activities(void) {
    printf("\n========== PROCESS ACTIVITIES ==========\n");

    for (int p = 0; p < process_count; p++) {
        printf("\nPID: %d\n", processes[p].pid);

        for (int e = 0; e < event_count; e++) {
            if (events[e].pid != processes[p].pid)
                continue;

            printf("  %-10s | %-7s | %s\n",
                   events[e].intent,
                   events[e].action,
                   events[e].path);
        }
    }
}

int main(int argc, char *argv[]) {
    const char *filename =
        argc > 1 ? argv[1] : "depsandbox.log";

    FILE *file = fopen(filename, "r");

    if (!file) {
        perror("Unable to open log file");
        return 1;
    }

    char line[MAX_LINE];

    while (fgets(line, sizeof(line), file)) {
        /* Ignore startup/shutdown lines that aren't event JSON. */
        if (!strstr(line, "\"intent\""))
            continue;

        total++;

        struct json_object *obj = json_tokener_parse(line);

        if (!obj ||
            !json_object_is_type(obj, json_type_object)) {
            malformed++;
            if (obj)
                json_object_put(obj);
            continue;
        }

        struct json_object *field;

        int pid = 0;
        int ppid = 0;
        const char *intent = NULL;
        const char *path = NULL;
        const char *action = NULL;

        if (json_object_object_get_ex(obj, "pid", &field))
            pid = json_object_get_int(field);

        if (json_object_object_get_ex(obj, "ppid", &field))
            ppid = json_object_get_int(field);

        if (json_object_object_get_ex(obj, "intent", &field))
            intent = json_object_get_string(field);

        if (json_object_object_get_ex(obj, "path", &field))
            path = json_object_get_string(field);

        if (json_object_object_get_ex(obj, "action", &field))
            action = json_object_get_string(field);

        if (pid <= 0 || !intent) {
            malformed++;
            json_object_put(obj);
            continue;
        }

        valid++;
        record_event(pid, ppid, intent, path, action);

        if (strcmp(intent, "FILE_READ") == 0)
            reads++;
        else if (strcmp(intent, "FILE_WRITE") == 0)
            writes++;
        else if (strcmp(intent, "FILE_DELETE") == 0)
            deletes++;
        else if (strcmp(intent, "CLONE") == 0)
            clones++;

        if (action && strcmp(action, "ALLOW") == 0)
            allowed++;
        else if (action && strcmp(action, "DENY") == 0)
            denied++;
        else if (action && strcmp(action, "ERROR") == 0)
            errors++;

        json_object_put(obj);
    }

    fclose(file);

    /* Existing security report. */
    printf("\n========== DEPSANDBOX SECURITY REPORT ==========\n");
    printf("Log file             : %s\n", filename);
    printf("Event records        : %d\n", total);
    printf("Valid events         : %d\n", valid);
    printf("Malformed events     : %d\n", malformed);

    printf("\n[OPERATION BREAKDOWN]\n");
    printf("File read requests   : %d\n", reads);
    printf("File write requests  : %d\n", writes);
    printf("Delete attempts      : %d\n", deletes);
    printf("Process creation     : %d\n", clones);

    printf("\n[RECORDED ACTIONS]\n");
    printf("ALLOW                : %d\n", allowed);
    printf("DENY                 : %d\n", denied);
    printf("ERROR                : %d\n", errors);

    printf("\n[PROCESS SUMMARY]\n");
    printf("Unique PIDs observed : %d\n", process_count);

    /* Print the hierarchy separately from activity details. */
    printf("\n========== PROCESS TREE ==========\n");

    int visited[MAX_PROCESSES];
    int visited_count = 0;

    /* Start with processes whose parents weren't observed. */
    for (int i = 0; i < process_count; i++) {
        if (find_process(processes[i].ppid) < 0 &&
            !is_visited(processes[i].pid,
                        visited, visited_count)) {
            print_tree(processes[i].pid, "", 1, 1,
                       visited, &visited_count);
        }
    }

    /* Include disconnected records or records in cycles. */
    for (int i = 0; i < process_count; i++) {
        if (!is_visited(processes[i].pid,
                        visited, visited_count)) {
            printf("\n[Unconnected process records]\n");

            print_tree(processes[i].pid, "", 1, 1,
                       visited, &visited_count);
        }
    }

    printf("==================================\n");

    /* Preserve all per-process event details. */
    print_activities();

    return 0;
}
