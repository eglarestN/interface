#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 1514
#define CONFIG_FILE "config.txt"
#define WRITE_THRESHOLD 100 // Her 100 satırda bir dosyaya yazma yapılacak

FILE *traffic_file = NULL;
int line_count = 0; // Dosyadaki satır sayısını takip etmek için sayaç

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    time_t now = time(0);
    struct tm *local_time = localtime(&now);

    if (traffic_file == NULL)
        traffic_file = fopen("/usr/local/www/network_traffic.txt", "a");

    unsigned char protocol = packet[23];
    if (protocol == 6) {
        fprintf(traffic_file, "Bu bir TCP paketi ");
    } else {
        fprintf(traffic_file, "Bu bir TCP paketi değil ");
    }

    fprintf(traffic_file, "[%d-%02d-%02d %02d:%02d:%02d] ",
            local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
    fprintf(traffic_file, "Source IP: %d.%d.%d.%d ", packet[26], packet[27], packet[28], packet[29]);
    fprintf(traffic_file, "Destination IP: %d.%d.%d.%d ", packet[30], packet[31], packet[32], packet[33]);
    fprintf(traffic_file, "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x ", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    fprintf(traffic_file, "Source Port: %u ", (packet[36] << 8) | packet[37]);
    fprintf(traffic_file, "Destination Port: %u ", (packet[38] << 8) | packet[39]);

    const unsigned char *tcp_data = packet + 54; //tcp alanının başlangıcı için 54 byte sonrası tcp data işaretcisi oluyor
    int tcp_data_length = pkthdr->len - 54; // tcp alanının net uzunluğu 

    // eğer ağ üzerinde get istekleri varsa yakalanması için 
    if (tcp_data_length > 0 && memcmp(tcp_data, "GET ", 4) == 0) { // tcp paketi varsa ve bu datanı ilk 4 bytı get ise 
        const unsigned char *host_start = strstr((const char *)tcp_data, "Host: "); // host dizesinin başlangıcı bulmak için 
        if (host_start != NULL) {
            host_start += 6; // host: kelimesini geçerek urlnin başına gecer 
            const unsigned char *host_end = (const unsigned char *)strchr((const char *)host_start, '\r'); // urlnin sonunun belirlenmesi için 
            if (host_end != NULL) {
                int host_length = host_end - host_start; // urlnin uzunluğu
                char host[host_length + 1];
                memcpy(host, host_start, host_length); // host adında bir dize oluşturulur ve veriler kopyalanır 
                host[host_length] = '\0';

                fprintf(traffic_file, "URL: http://%s \n", host);
            }
        }
    }

    fflush(traffic_file);

    line_count++; // Satır sayısını artır

    // Her WRITE_THRESHOLD satırda bir dosyaya yazma işlemi gerçekleştir
    if (line_count >= WRITE_THRESHOLD) {
        fclose(traffic_file); // Dosyayı kapat
        traffic_file = fopen("/usr/local/www/network_traffic.txt", "a"); // Yeniden aç

        line_count = 0; // Sayaçı sıfırla
    }
}

void start_capture(const char *interface, const char *filter_exp) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask, net;

    handle = pcap_open_live(interface, BUFSIZE, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
}

int main() {
    FILE *config_file = fopen(CONFIG_FILE, "r");
    char line[100], *token, interface[100], port_str[100];
    
    while (fgets(line, sizeof(line), config_file)) {
        token = strtok(line, "=");
        if (strcmp(token, "interface") == 0) {
            strcpy(interface, strtok(NULL, "\n"));
        } else if (strcmp(token, "port") == 0) {
            strcpy(port_str, strtok(NULL, "\n"));
        }
    }
    fclose(config_file);

    char *token_port = strtok(port_str, ",");
    while (token_port != NULL) {
        char filter_exp[50];

        if (strncmp(token_port, "TCP", 3) == 0) {
            if (strstr(token_port, "80") != NULL || strstr(token_port, "443") != NULL) {
                sprintf(filter_exp, "tcp port 80 or tcp port 443");
                start_capture(interface, filter_exp);
            }
        } else if (strncmp(token_port, "UDP", 3) == 0) {
            int port = atoi(token_port + 4);
            if (port == 21 || port == 50) {
                sprintf(filter_exp, "udp port %d", port);
                start_capture(interface, filter_exp);
            }
        } else {
            int port = atoi(token_port);
            sprintf(filter_exp, "tcp port %d", port);
            start_capture(interface, filter_exp);
        }

        token_port = strtok(NULL, ",");
    }

    if (traffic_file != NULL) {
        fclose(traffic_file);
        traffic_file = NULL;
    }

    return 0;
}