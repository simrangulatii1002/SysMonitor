// DatabaseInitializer.h
#pragma once

#include "DatabaseConnector.h"
#include "DbStructure.h"
#include "DatabaseHandler.h"

class DatabaseInitializer {
public:
    DatabaseInitializer(const std::string& server, const std::string& username, const std::string& password);
    bool initializeDatabase();
    void insertSystemInformation(const std::string& ipAddr, const std::string& ram, const std::string& cpu, const std::string& idle, const std::string& hdd, const std::string& netw);
private:
    DatabaseConnector dbConnector;
    DatabaseHandler dbHandler;
};
