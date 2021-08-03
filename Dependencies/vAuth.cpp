// Auravyx-Auth-Server.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <chrono>
#include <cstdio>
#include "HTTP/HTTP.h"
#include <atomic>
#include "SHA256/SHA_256.h"
#include <map>

#define SERVER_CERT_FILE "./cert.pem"
#define SERVER_PRIVATE_KEY_FILE "./key.pem"

std::vector<std::string> splitString(std::string string, std::string splitter)
{
    std::vector<std::string> splitStr;
    int lastIndex = 0;
    for (int i = 0; i < string.length(); i++)
    {
        if (string.at(i) == splitter.at(0))
        {
            std::string split = string.substr(lastIndex, i - lastIndex);
            lastIndex = i + 1;
            if (split.length() > 0)
            {
                splitStr.emplace_back(split);
            }
        }
    }
    std::string split = string.substr(lastIndex, string.length() - lastIndex);
    if (split.length() > 0)
    {
        splitStr.emplace_back(split);
    }
    return splitStr;
}

std::string readTextFile(std::string location)
{
    std::ifstream inStream(location, std::ifstream::in);
    std::stringstream stream;
    stream << inStream.rdbuf();

    return stream.str();
}
std::vector<std::string> readLines(std::string location)
{
    std::string file = readTextFile(location);
    std::vector<std::string> lines = splitString(file, "\n");
    return lines;
}

std::vector<std::string> getInput() 
{
    std::string c;
    std::vector<std::string> cl;
    std::string line;
    std::getline(std::cin, line);
    std::istringstream iss(line);
    while (iss >> c) 
    {
        cl.emplace_back(c);
    }
    return cl;
}
void writeToFile(std::string dir, std::string data)
{
    std::ofstream file;
    file.open(dir);
    file << data;
    file.close();
}

std::map<std::string, std::string> accounts;

void addUser(std::string username, std::string password)
{
    std::map<std::string, std::string>::iterator it = accounts.find(username);
    if (it != accounts.end())
    {
        std::cout << "[Auravyx] : User '" << username << "' already exists!\n";
        return;
    }
    std::string hashed;
    SHA_256::hash256_hex_string(password, hashed);

    accounts.emplace(username, hashed);

    std::cout << "[Auravyx] : User added (" << username << ", " << password << ").\n";
}

bool isUser(std::string username, std::string password)
{
    std::map<std::string, std::string>::iterator it = accounts.find(username);
    if (it != accounts.end())
    {
        std::string hashedPass = it->second;

        std::string hashedInput;
        SHA_256::hash256_hex_string(password, hashedInput);

        if (hashedPass.compare(hashedInput) == 0)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    return false;
}
bool t = false;
void getConsoleInput()
{
    while(true)
    {
        std::cout << "[Auravyx] : ";
        std::string input = "";
        std::vector<std::string> command = getInput();

        if (command.size() > 0)
        {
            if (command.size() == 3 && command.at(0).compare("adduser") == 0)
            {
                addUser(command.at(1), command.at(2));
            }
            if (command.size() == 3 && command.at(0).compare("isuser") == 0)
            {
                bool is = isUser(command.at(1), command.at(2));
                std::cout << "[Auravyx] : ";
                if (is)
                {
                    std::cout << "User exists!\n";
                }
                else
                {
                    std::cout << "User does not exist!\n";
                }
            }
            if (command.size() == 1 && command.at(0).compare("save") == 0)
            {
                std::string accountString = "";

                std::map<std::string, std::string>::iterator it;

                for (it = accounts.begin(); it != accounts.end(); it++)
                {
                    accountString += it->first;
                    accountString += ' ';
                    accountString += it->second;
                    accountString += '\n';
                }
                writeToFile("./accounts.txt", accountString);
                
                std::cout << "[Auravyx] : Saved accounts to disk." << "\n";
            }
            if (command.size() == 1 && command.at(0).compare("stop") == 0)
            {
                return;
            }
        }
    }
}

std::string dump_headers(const HTTP::Headers& headers)
{
    std::string s;
    char buf[BUFSIZ];
    
    for (auto it = headers.begin(); it != headers.end(); ++it) {
        const auto& x = *it;
        snprintf(buf, sizeof(buf), "%s: %s\n", x.first.c_str(), x.second.c_str());
        s += buf;
    }

    return s;
}

std::string log(const HTTP::Request& req, const HTTP::Response& res) {
    std::string s;
    char buf[BUFSIZ];

    s += "================================\n";

    snprintf(buf, sizeof(buf), "%s %s %s", req.method.c_str(),
        req.version.c_str(), req.path.c_str());
    s += buf;
    std::string query;
    for (auto it = req.params.begin(); it != req.params.end(); ++it) {
        const auto& x = *it;
        snprintf(buf, sizeof(buf), "%c%s=%s",
            (it == req.params.begin()) ? '?' : '&', x.first.c_str(),
            x.second.c_str());
        query += buf;
    }
    snprintf(buf, sizeof(buf), "%s\n", query.c_str());
    s += buf;

    s += dump_headers(req.headers);

    s += "--------------------------------\n";

    snprintf(buf, sizeof(buf), "%d %s\n", res.status, res.version.c_str());
    s += buf;
    s += dump_headers(res.headers);
    s += "\n";

    if (!res.body.empty()) { s += res.body; }

    s += "\n";

    return s;
}
HTTP::SSLServer* svr;
int client()
{
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    svr = new HTTP::SSLServer(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
#else
    HTTP::Server svr;
#endif
    HTTP::Server dd;
    if (!svr->is_valid())
    {
        printf("server has an error...\n");
        return -1;
    }

    svr->Get("/", [=](const HTTP::Request& /*req*/, HTTP::Response& res)
        {
            res.set_redirect("/hi");
        });

    svr->Get("/hi", [](const HTTP::Request& /*req*/, HTTP::Response& res)
        {
            res.set_content("Hello World!\n", "text/plain");
        });

    svr->Get("/authenticate", [](const HTTP::Request&req, HTTP::Response& res)
    {
        std::string username = req.get_header_value("username");
        std::string password = req.get_header_value("password");
        bool user = isUser(username, password);

        if (user)
        {
            std::cout << "[Auravyx] : '" << username << "' has successfully connected!\n";
            std::cout << "[Auravyx] : -> IP: " << req.remote_addr << " Port: " << req.remote_port << "\n";
            res.set_content("Connected!\n", "text/plain");
        }
        else
        {
            std::cout << "[Auravyx] : '" << username << "'tried to connect, but the username or password does not exist!\n";
            std::cout << "[Auravyx] : -> IP: " << req.remote_addr << " Port: " << req.remote_port << "\n";
            res.set_content("Thats not a user!\n", "text/plain");
        }
    });

    svr->Get("/dump", [](const HTTP::Request& req, HTTP::Response& res) {
        //res.set_content(dump_headers(req.headers), "text/plain");
        });

    svr->Get("/stop",
        [&](const HTTP::Request& /*req*/, HTTP::Response& /*res*/) { svr->stop(); });
    svr->Post("/multipart", [&](const auto& req, auto& res) {
        auto size = req.files.size();
        auto ret = req.has_file("name1");
        const auto& file = req.get_file_value("name1");
        // file.filename;
        // file.content_type;
        // file.content;
        std::cout << "WAH!";
        });
    svr->set_error_handler([](const HTTP::Request& /*req*/, HTTP::Response& res) {
        const char* fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), fmt, res.status);
        res.set_content(buf, "text/html");
        });

    svr->set_logger([](const HTTP::Request& req, const HTTP::Response& res) {
        printf("%s", log(req, res).c_str());
        });
    

    std::cout << "Now listening";
    svr->listen("6.9.6.9", 443);
    return 1;
}

int main(void) 
{
    std::string file = readTextFile("./accounts.txt");
    if (file.size() != 0)
    {
        std::vector<std::string> lines = readLines("./accounts.txt");
        std::cout << lines.size() << " users found.\n";
        for (auto s : lines)
        {
            std::vector<std::string> split = splitString(s, " ");
            accounts.emplace(split.at(0), split.at(1));
        }
    }
    std::thread clientThread(client);

    getConsoleInput();

    svr->stop();
    delete svr;
    clientThread.join();
    return 0;
}