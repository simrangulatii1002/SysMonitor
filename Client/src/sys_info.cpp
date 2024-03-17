#include<sys_info.h>
#include <sys/statvfs.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

// Get the system hostname
std::string getHostname() {
    char hostname[1024];
    gethostname(hostname, 1024);
    return std::string(hostname);
}

// Get the system IP address
std::string getIPAddress() {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    std::string ip_address;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        // Check if the interface name matches the Ethernet interface name
        if (std::string(ifa->ifa_name) == "enp0s3") {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
            ip_address = std::string(ip);
            break;
        }
    }

    freeifaddrs(ifaddr);
    return ip_address;
}

// Get CPU usage
double getCPUUsage() {
    // Read /proc/stat and calculate CPU usage
    std::ifstream file("/proc/stat");
    std::string line;
    long user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    getline(file, line);
    std::istringstream iss(line);
    iss >> line >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;

    long idle_time = idle + iowait;
    long non_idle_time = user + nice + system + irq + softirq + steal;
    long total_time = idle_time + non_idle_time;

    return (1.0 - static_cast<double>(idle_time) / total_time) * 100.0;
}

// Get RAM usage
long getRAMUsage() {
    std::ifstream file("/proc/meminfo");
    std::string line;
    long totalMem = 0, freeMem = 0;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key;
        long value;
        iss >> key >> value;
        if (key == "MemTotal:") totalMem = value;
        if (key == "MemFree:") freeMem = value;
    }
    return (totalMem - freeMem);
}

// Get network stats
std::string getNetworkStats() {
    std::ifstream file("/proc/net/route");
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open /proc/net/route" << std::endl;
        return "error";
    }

    // Skip the first line (header)
    std::string line;
    std::getline(file, line);

    // Check if there are any routes in the file
    if (file.peek() == std::ifstream::traits_type::eof()) {
        return "disconnected"; // No routes found, not connected to any network
    }

    return "connected"; // Connected to a network
}

//Get hddutilization
std::string getHDDUtilization() {
    struct statvfs buffer;
    if (statvfs("/", &buffer) != 0) {
        // Error occurred while retrieving disk usage
        return "Error: Unable to retrieve HDD utilization";
    }

    // Calculate HDD utilization percentage
    double totalSpace = (double)(buffer.f_blocks * buffer.f_frsize);
    double freeSpace = (double)(buffer.f_bfree * buffer.f_frsize);
    double usedSpace = totalSpace - freeSpace;
    double utilizationPercentage = (usedSpace / totalSpace) * 100.0;

    return std::to_string(utilizationPercentage) + "%";
}

// Get system idle time
long getIdleTime() {
    std::ifstream file("/proc/stat");
    std::string line;
    getline(file, line);
    std::istringstream iss(line);
    std::string label;
    long user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    iss >> label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;
    return idle;
}
