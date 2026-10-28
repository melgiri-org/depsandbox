
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define MAX_PROCESSES 2048
#define MAX_LINE 8192

typedef struct {
    int pid;
    int ppid;
    int events;
} Process;

Process processes[MAX_PROCESSES];
int process_count = 0;

int find_process(int pid) {
    for (int i = 0; i < process_count; i++) {
        if (processes[i].pid == pid)
            return i;
    }
    return -1;
}

void record_process(int pid, int ppid) {
    if (pid <= 0)
        return;

    int index = find_process(pid);

    if (index < 0) {
        if (process_count >= MAX_PROCESSES)
            return;

        index = process_count++;
        processes[index].pid = pid;
        processes[index].ppid = ppid;
        processes[index].events = 0;
    }

    processes[index].events++;

    if (processes[index].ppid <= 0 && ppid > 0)
        processes[index].ppid = ppid;
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

    int total = 0;
    int valid = 0;
    int malformed = 0;
    int reads = 0;
    int writes = 0;
    int deletes = 0;
    int clones = 0;
    int allowed = 0;
    int denied = 0;
    int errors = 0;

    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "\"intent\"") == NULL)
            continue;

        total++;

        struct json_object *event =
            json_tokener_parse(line);

        if (!event || !json_object_is_type(
                          event, json_type_object)) {
            malformed++;
            if (event)
                json_object_put(event);
            continue;
        }

        struct json_object *field;
        int pid = 0, ppid = 0;

        if (json_object_object_get_ex(event, "pid", &field))
            pid = json_object_get_int(field);

        if (json_object_object_get_ex(event, "ppid", &field))
            ppid = json_object_get_int(field);

        if (pid <= 0) {
            malformed++;
            json_object_put(event);
            continue;
        }

        valid++;
        record_process(pid, ppid);

        if (json_object_object_get_ex(event, "intent", &field)) {
            const char *intent = json_object_get_string(field);

            if (intent && strcmp(intent, "FILE_READ") == 0)
                reads++;
            else if (intent && strcmp(intent, "FILE_WRITE") == 0)
                writes++;
            else if (intent && strcmp(intent, "FILE_DELETE") == 0)
                deletes++;
            else if (intent && strcmp(intent, "CLONE") == 0)
                clones++;
        }

        if (json_object_object_get_ex(event, "action", &field)) {
            const char *action = json_object_get_string(field);

            if (action && strcmp(action, "ALLOW") == 0)
                allowed++;
            else if (action && strcmp(action, "DENY") == 0)
                denied++;
            else if (action && strcmp(action, "ERROR") == 0)
                errors++;
        }

        json_object_put(event);
    }

    fclose(file);

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

    printf("\n================================================\n");


    return 0;
}
