#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>


std::string getHostname();
std::string getIPAddress();
double getCPUUsage();
long getRAMUsage();
std::string getNetworkStats();
std::string getHDDUtilization(); 
long getIdleTime(); 