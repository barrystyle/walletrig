#ifndef LISTDB_H
#define LISTDB_H

#include <fstream>

size_t total_size();
void load_pwlist_db();
void password_at(size_t pos, std::string& password);
void next_password(std::string& password);

#endif // LISTDB_H
