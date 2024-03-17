#pragma once
#include <string>
#include <mysql_driver.h>
#include <cppconn/connection.h>
using namespace sql;
class DbStructure {
public:
    static DbStructure &getInstance(sql::Connection *dbConnection);
    void CreateDb();
    void CreateTables();

private:
    DbStructure(sql::Connection *dbConnection);
    sql::Connection *dbConnection;
};
