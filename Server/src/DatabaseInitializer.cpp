// DatabaseInitializer.cpp
#include "DatabaseInitializer.h"

DatabaseInitializer::DatabaseInitializer(const std::string& server, const std::string& username, const std::string& password)
    : dbConnector(server, username, password), dbHandler(dbConnector.dbConnection) {}

bool DatabaseInitializer::initializeDatabase() {
    if (!dbConnector.connectToDatabase()) {
        std::cerr << "Failed to connect to the database." << std::endl;
        return false;
    }

    DbStructure dbStructure = DbStructure::getInstance(dbConnector.dbConnection);
    dbStructure.CreateDb();
    dbStructure.CreateTables();

    return true;
}

void DatabaseInitializer::insertSystemInformation(const std::string& ipAddr, const std::string& ram, const std::string& cpu, const std::string& idle, const std::string& hdd, const std::string& netw) {
    if (!dbHandler.clientExists(ipAddr)) {
        dbHandler.insertClientDetail(ipAddr, "hostname"); // Example hostname, replace with actual value
    }

    dbHandler.insertSysteminfo(ipAddr, ram, cpu, idle, hdd, netw);
}
