#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define _XOPEN_SOURCE 700  // Ensure POSIX compliance

#include <stdint.h>  // For uint8_t and other data types
#include <sys/types.h>  // For u_int, u_short, u_char, and other data types

#define SNAP_LEN 1518  // Maximum capture length
#define SIZE_ETHERNET 14  // Ethernet header length
#define RULE_FILE "rules.conf"
#define MAX_RULES 100  // Maximum number of rules
#define LINE_LEN 200   // Maximum line length
#define LOG_FILE "packet_broker.log"
#define STATUS_FILE "packet_broker.status"
#define PID_FILE "packet_broker.pid"

typedef struct {
    char interface_in[10];
    char tcp_flags[10];
    int dest_port;
    char protocol[10];  // Protocol type (e.g., "TCP", "UDP", "ICMP")
    int vlan_id;        // VLAN ID (0 if none)
    char string_match[50]; // Specific string (e.g., "abc")
    int exclude;        // 1 if this rule is for exclusion
    char interface_out[10];
    int priority;       // Rule priority
    time_t start_time;
    time_t end_time;
    struct tm priority_start_time;  // Start time for priority
    struct tm priority_end_time;    // End time for priority
} rule_t;

typedef struct {
    pcap_t *handle;
    int rule_index;
} thread_args_t;

rule_t rules[MAX_RULES];
int rule_count = 0;
time_t last_modified_time = 0;

// Packet handler
void *packet_thread(void *args);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Helper functions
void send_packet(const u_char *packet, int length, const char *interface_name);
int check_tcp_flags(const struct tcphdr *tcp, const char *flags);
int match_protocol(const struct ip *ip_header, const char *protocol);
int match_vlan(const u_char *packet, int vlan_id);
int match_string(const u_char *payload, int payload_len, const char *string_match);
void load_rules();
void check_for_updates();
void add_rule(rule_t new_rule);
void remove_rule(int index);
int is_rule_active(rule_t *rule);
int is_time_in_range(struct tm *current_time, struct tm *start_time, struct tm *end_time);

// Write to log file
void write_log(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s\n", message);
        fclose(log_file);
    } else {
        perror("Error opening log file");
    }
}

// Write to status file
void write_status(const char *status) {
    FILE *status_file = fopen(STATUS_FILE, "w");
    if (status_file != NULL) {
        fprintf(status_file, "%s\n", status);
        fclose(status_file);
    }
}

// Write to PID file
void write_pid() {
    FILE *pid_file = fopen(PID_FILE, "w");
    if (pid_file != NULL) {
        fprintf(pid_file, "%d\n", getpid());
        fclose(pid_file);
    }
}

int main(int argc, char *argv[]) {
    write_status("running");
    write_pid();
    char errbuf[PCAP_ERRBUF_SIZE];
    pthread_t threads[MAX_RULES];

    // Load rules
    load_rules();

    for (int i = 0; i < rule_count; i++) {
        pcap_t *handle = pcap_open_live(rules[i].interface_in, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", rules[i].interface_in, errbuf);
            return 2;
        }
        printf("Listening on %s, redirecting matching packets to %s\n", rules[i].interface_in, rules[i].interface_out);

        thread_args_t *args = (thread_args_t *)malloc(sizeof(thread_args_t));
        args->handle = handle;
        args->rule_index = i;

        // Create a new thread
        if (pthread_create(&threads[i], NULL, packet_thread, (void *)args) != 0) {
            fprintf(stderr, "Error creating thread for %s\n", rules[i].interface_in);
            return 2;
        }
    }

    // Wait for threads to finish
    for (int i = 0; i < rule_count; i++) {
        pthread_join(threads[i], NULL);
    }

    write_status("stopped");
    return 0;
}

// Thread function
void *packet_thread(void *args) {
    thread_args_t *targs = (thread_args_t *)args;
    pcap_loop(targs->handle, 0, packet_handler, (u_char *)&targs->rule_index);
    pcap_close(targs->handle);
    free(targs);
    pthread_exit(NULL);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int packet_count = 0;
    int rule_index = *((int *)args);
    struct ip *ip_header = (struct ip *)(packet + SIZE_ETHERNET);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + SIZE_ETHERNET + ip_header->ip_hl * 4);
    const u_char *payload = packet + SIZE_ETHERNET + ip_header->ip_hl * 4 + tcp_header->th_off * 4;
    int payload_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4 + tcp_header->th_off * 4);

    if (!is_rule_active(&rules[rule_index])) {
        return;
    }

    int match = 1;

    // Protocol check
    if (strlen(rules[rule_index].protocol) > 0 && !match_protocol(ip_header, rules[rule_index].protocol)) {
        match = 0;
    }

    // VLAN check
    if (rules[rule_index].vlan_id != 0 && !match_vlan(packet, rules[rule_index].vlan_id)) {
        match = 0;
    }

    // TCP flags check
    if (strlen(rules[rule_index].tcp_flags) > 0 && !check_tcp_flags(tcp_header, rules[rule_index].tcp_flags)) {
        match = 0;
    }

    // String match
    if (strlen(rules[rule_index].string_match) > 0 && !match_string(payload, payload_len, rules[rule_index].string_match)) {
        match = 0;
    }

    // Exclude check
    if (rules[rule_index].exclude == 1) {
        match = !match;
    }

    if (match) {
        packet_count++;
        if (packet_count % 100 == 0) {
            printf("Matching packet: Redirecting from %s to %s\n", rules[rule_index].interface_in, rules[rule_index].interface_out);
        }
        send_packet(packet, header->len, rules[rule_index].interface_out);
    }
}

int check_tcp_flags(const struct tcphdr *tcp, const char *flags) {
    u_int8_t th_flags = tcp->th_flags;

    // Check flags
    if (strchr(flags, 'S') && !(th_flags & TH_SYN)) return 0;
    if (strchr(flags, 'F') && !(th_flags & TH_FIN)) return 0;
    if (strchr(flags, 'R') && !(th_flags & TH_RST)) return 0;
    if (strchr(flags, 'P') && !(th_flags & TH_PUSH)) return 0;
    if (strchr(flags, 'A') && !(th_flags & TH_ACK)) return 0;
    if (strchr(flags, 'U') && !(th_flags & TH_URG)) return 0;

    return 1;
}

int match_protocol(const struct ip *ip_header, const char *protocol) {
    if (strcmp(protocol, "TCP") == 0 && ip_header->ip_p == IPPROTO_TCP) return 1;
    if (strcmp(protocol, "UDP") == 0 && ip_header->ip_p == IPPROTO_UDP) return 1;
    if (strcmp(protocol, "ICMP") == 0 && ip_header->ip_p == IPPROTO_ICMP) return 1;
    return 0;
}

int match_vlan(const u_char *packet, int vlan_id) {
    // Ethernet frame VLAN check
    u_int16_t tci = ntohs(*(u_int16_t *)(packet + 14));
    int vlan = tci & 0x0FFF;
    return vlan == vlan_id;
}

int match_string(const u_char *payload, int payload_len, const char *string_match) {
    if (payload_len <= 0) return 0;
    if (strstr((const char *)payload, string_match) != NULL) return 1;
    return 0;
}

void send_packet(const u_char *packet, int length, const char *interface_name) {
    static pcap_t *handles[MAX_RULES];
    static char *opened_interfaces[MAX_RULES];
    static int handle_count = 0;
    pcap_t *handle = NULL;

    // Reuse already opened interface handle
    for (int i = 0; i < handle_count; i++) {
        if (strcmp(opened_interfaces[i], interface_name) == 0) {
            handle = handles[i];
            break;
        }
    }

    if (handle == NULL) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(interface_name, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", interface_name, errbuf);
            return;
        }

        // Add newly opened interface and handle to the list
        handles[handle_count] = handle;
        opened_interfaces[handle_count] = strdup(interface_name);
        handle_count++;
    }

    // Check packet size and perform fragmentation
    int offset = 0;
    while (offset < length) {
        int send_len = (length - offset > SNAP_LEN) ? SNAP_LEN : (length - offset);

        if (pcap_inject(handle, packet + offset, send_len) == -1) {
            pcap_perror(handle, "Error sending packet");
            return;
        }

        offset += send_len;
    }
}

void parse_time(const char *time_str, struct tm *time_struct) {
    sscanf(time_str, "%2d:%2d", &time_struct->tm_hour, &time_struct->tm_min);
}

void load_rules() {
    FILE *file = fopen(RULE_FILE, "r");
    if (file == NULL) {
        perror("Error opening rules file");
        exit(EXIT_FAILURE);
    }

    rule_count = 0;
    char line[LINE_LEN];
    int line_number = 0;  // To track line numbers

    while (fgets(line, sizeof(line), file)) {
        line_number++;
        if (line_number == 1 || strlen(line) == 0 || line[0] == '\n') {
            continue;
        }

        // Remove newline character from the line
        line[strcspn(line, "\n")] = 0;

        if (line[0] == '#') {
            continue;
        }

        printf("Reading line: %s\n", line);

        char *token;
        int field_count = 0;
        rule_t new_rule = {0};

        token = strtok(line, ",");
        while (token != NULL) {
            switch (field_count) {
                case 0:
                    strncpy(new_rule.interface_in, token, sizeof(new_rule.interface_in) - 1);
                    break;
                case 1:
                    if (*token != '\0') strncpy(new_rule.tcp_flags, token, sizeof(new_rule.tcp_flags) - 1);
                    break;
                case 2:
                    new_rule.dest_port = atoi(token);
                    break;
                case 3:
                    if (*token != '\0') strncpy(new_rule.protocol, token, sizeof(new_rule.protocol) - 1);
                    break;
                case 4:
                    new_rule.vlan_id = atoi(token);
                    break;
                case 5:
                    if (*token != '\0') strncpy(new_rule.string_match, token, sizeof(new_rule.string_match) - 1);
                    break;
                case 6:
                    new_rule.exclude = atoi(token);
                    break;
                case 7:
                    strncpy(new_rule.interface_out, token, sizeof(new_rule.interface_out) - 1);
                    break;
                case 8:
                    new_rule.priority = atoi(token);
                    break;
                case 9:
                    // Start time (e.g., in the format 08:00)
                    parse_time(token, &new_rule.priority_start_time);
                    break;
                case 10:
                    // End time (e.g., in the format 18:00)
                    parse_time(token, &new_rule.priority_end_time);
                    break;
            }
            token = strtok(NULL, ",");
            field_count++;
        }

        if (strlen(new_rule.interface_in) == 0 || strlen(new_rule.interface_out) == 0) {
            printf("Error: Missing interface_in or interface_out in rule %d, skipping\n", rule_count + 1);
            continue;
        }

        add_rule(new_rule);
    }
    fclose(file);
    printf("Loaded %d rules\n", rule_count);
}

void check_for_updates() {
    struct stat file_stat;
    if (stat(RULE_FILE, &file_stat) == 0) {
        if (file_stat.st_mtime != last_modified_time) {
            last_modified_time = file_stat.st_mtime;
            printf("Rules file updated, reloading rules...\n");
            load_rules();  // Reload rules
        }
    }
}

void add_rule(rule_t new_rule) {
    if (rule_count >= MAX_RULES) {
        fprintf(stderr, "Maximum number of rules exceeded\n");
        return;
    }

    rules[rule_count] = new_rule;
    rule_count++;

    printf("New rule added: Interface %s to %s\n", new_rule.interface_in, new_rule.interface_out);
}

void remove_rule(int index) {
    if (index < 0 || index >= rule_count) {
        fprintf(stderr, "Invalid rule index\n");
        return;
    }

    // Shift rules to remove the specified one
    for (int i = index; i < rule_count - 1; i++) {
        rules[i] = rules[i + 1];
    }

    rule_count--;

    printf("Rule at index %d removed\n", index);
}

int is_time_in_range(struct tm *current_time, struct tm *start_time, struct tm *end_time) {
    if (start_time->tm_hour < end_time->tm_hour ||
        (start_time->tm_hour == end_time->tm_hour && start_time->tm_min < end_time->tm_min)) {
        // Normal time range
        return (current_time->tm_hour > start_time->tm_hour ||
                (current_time->tm_hour == start_time->tm_hour && current_time->tm_min >= start_time->tm_min)) &&
               (current_time->tm_hour < end_time->tm_hour ||
                (current_time->tm_hour == end_time->tm_hour && current_time->tm_min <= end_time->tm_min));
    } else {
        // Time range crossing midnight
        return (current_time->tm_hour > start_time->tm_hour ||
                (current_time->tm_hour == start_time->tm_hour && current_time->tm_min >= start_time->tm_min)) ||
               (current_time->tm_hour < end_time->tm_hour ||
                (current_time->tm_hour == end_time->tm_hour && current_time->tm_min <= end_time->tm_min));
    }
}

int is_rule_active(rule_t *rule) {
    time_t current_time_raw = time(NULL);
    struct tm current_time;
    localtime_r(&current_time_raw, &current_time);

    // Check if the rule is active within the priority time range
    if (is_time_in_range(&current_time, &rule->priority_start_time, &rule->priority_end_time)) {
        return 1;  // This rule will be active within the specified time range
    }

    // Check the overall validity of the rule
    return (current_time_raw >= rule->start_time && current_time_raw <= rule->end_time);
}
