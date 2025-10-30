#include "db.h"
#include "listdb.h"

size_t list_sz, list_pos;
std::vector<std::string> password_list;

void load_pwlist_db()
{
    std::ifstream file("../kaonashi14M.txt");

    std::string line;
    while (std::getline(file, line)) {
        if (line.size() > 4)
            password_list.push_back(line);
    }
    list_pos = 0;
    list_sz = password_list.size();
    printf("read %d passwords into vector\n", (int)list_sz);
}

size_t total_size()
{
    return password_list.size();
}

void password_at(size_t pos, std::string& password)
{
    password = password_list[pos];
}

void next_password(std::string& password)
{
    password = password_list[list_pos++];
}
