// Auravyx-Auth-Server.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <chrono>
#include <cstdio>
#include "HTTP/HTTP.h"
#include <atomic>
#include "SHA256/SHA_256.h"
#include <map>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/ostreamwrapper.h"
#include "rapidjson/prettywriter.h"
#include <cstdint>
#include <cstddef>
#include <limits>

#define SERVER_CERT_FILE "./cert.pem"
#define SERVER_PRIVATE_KEY_FILE "./key.pem"

std::string clientID = "REDACTED";

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

const unsigned char from_base64[] = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255,  62, 255,  63,
                                     52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 255, 255, 255,
                                    255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
                                     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255,  63,
                                    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
                                     41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255 };

std::vector<unsigned char> decode64(std::string encoded_string)
{
    // Make sure string length is a multiple of 4
    while ((encoded_string.size() % 4) != 0)
        encoded_string.push_back('=');

    size_t encoded_size = encoded_string.size();
    std::vector<unsigned char> ret;
    ret.reserve(3 * encoded_size / 4);

    for (size_t i = 0; i < encoded_size; i += 4)
    {
        unsigned char b4[4];
        b4[0] = (encoded_string[i + 0] <= 'z') ? from_base64[encoded_string[i + 0]] : 0xff;
        b4[1] = (encoded_string[i + 1] <= 'z') ? from_base64[encoded_string[i + 1]] : 0xff;
        b4[2] = (encoded_string[i + 2] <= 'z') ? from_base64[encoded_string[i + 2]] : 0xff;
        b4[3] = (encoded_string[i + 3] <= 'z') ? from_base64[encoded_string[i + 3]] : 0xff;

        unsigned char b3[3];
        b3[0] = ((b4[0] & 0x3f) << 2) + ((b4[1] & 0x30) >> 4);
        b3[1] = ((b4[1] & 0x0f) << 4) + ((b4[2] & 0x3c) >> 2);
        b3[2] = ((b4[2] & 0x03) << 6) + ((b4[3] & 0x3f) >> 0);

        if (b4[1] != 0xff) ret.push_back(b3[0]);
        if (b4[2] != 0xff) ret.push_back(b3[1]);
        if (b4[3] != 0xff) ret.push_back(b3[2]);
    }

    return ret;
}
uint32_t table[256];
uint32_t update(uint32_t(&table)[256], uint32_t initial, const void* buf, size_t len)
{
    uint32_t c = initial ^ 0xFFFFFFFF;
    const uint8_t* u = static_cast<const uint8_t*>(buf);
    for (size_t i = 0; i < len; ++i)
    {
        c = table[(c ^ u[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
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
    svr->Post("/payment", [&](const auto& req, auto& res) {
        auto size = req.files.size();
        auto ret = req.has_file("name1");
        const auto& file = req.get_file_value("name1");
        // file.filename;
        // file.content_type;
        // file.content;
        std::cout << "Payment!!\n\n";

        std::map<std::string, std::string> headers;
        for (auto h : req.headers)
        {
            headers.emplace(h.first, h.second);
        }
        const char* json = req.body.c_str();
        rapidjson::Document d;
        d.Parse(json);
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        d.Accept(writer);
        std::cout << buffer.GetString() << std::endl;
        std::cout << "\n!!!\n";
        std::map<std::string, std::string>::iterator itr = headers.find("PAYPAL-CERT-URL");
        if (itr != headers.end())
        {
            std::cout << "\n\n\n";
            int splitPoint = 0;
            for (int i = 0; i < itr->second.length(); i++)
            {
                if (itr->second.at(i) == '/')
                {
                    splitPoint++;
                }
                if (splitPoint == 3)
                {
                    splitPoint = i;
                    break;
                }
            }
            std::cout << "Split point: " << splitPoint << " msg: " << itr->second << "\n\n";
            if (itr->second.size() > splitPoint)
            {
                std::string urlStart = itr->second.substr(8, splitPoint - 8);
                std::string urlEnd = itr->second.substr(splitPoint, itr->second.length() - 1);
                HTTP::SSLClient paypal(urlStart, 443);
                //httplib::SSLClient cli("142.93.144.205", 443);
                // httplib::SSLClient cli("google.com");
                // httplib::SSLClient cli("www.youtube.com");
                paypal.enable_server_certificate_verification(false);
                std::cout << "Sending to '" << urlStart << "/" << urlEnd << "'\n";

                if (auto ress = paypal.Get(urlEnd.c_str()))
                {
                    //std::cout << res->status << std::endl;
                    //std::cout << res->get_header_value("Content-Type") << std::endl;
                    //std::cout << res->body << std::endl;


                    std::vector<unsigned char> signature = decode64(headers.at("PAYPAL-TRANSMISSION-SIG"));
                    unsigned char sigArr[256];
                    for (int i = 0; i < 256; i++)
                    {
                        sigArr[i] = signature.at(i);
                    }
                    writeToFile("./hack.txt", headers.at("PAYPAL-TRANSMISSION-SIG"));
                    const char* certStr = ress->body.c_str();
                    BIO* bio_mem = BIO_new(BIO_s_mem());
                    BIO_puts(bio_mem, certStr);
                    X509* x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
                    EVP_PKEY* pkey = X509_get_pubkey(x509);
                    int r = X509_verify(x509, pkey);
                    RSA* rsa_pubkey;
                    rsa_pubkey = EVP_PKEY_get1_RSA(pkey);
                    std::string webhookID = "1DG22107M37735804";
                    //webhookID = d["resource"]["id"].GetString();
                    uint32_t crc32 = 0;
                    crc32 = update(table, 0, req.body.c_str(), req.body.length());
                    std::string webhookEvent = std::to_string(crc32);

                    //string expectedSignature = String.Format("{0}|{1}|{2}|{3}", transmissionId,
                    //    transmissionTime, webhookId, hash);

                    std::string transmissionID = headers.at("PAYPAL-TRANSMISSION-ID");
                    std::string transmissionTime = headers.at("PAYPAL-TRANSMISSION-TIME");

                    std::string expectedSignature = transmissionID + "|" + transmissionTime + "|" + webhookID + "|" + webhookEvent;

                    std::cout << "Expected sig : " << expectedSignature << "\n";
                    /////(unsigned char*)res->body.c_str() should be smth

                    const unsigned char* constStr = reinterpret_cast<const unsigned char*> (expectedSignature.c_str());
                    std::cout << "String: " << constStr << ".\n";
                    int RESULT = RSA_verify(NID_sha1, constStr, expectedSignature.length(), sigArr,
                        256, rsa_pubkey);
                    char buf[512];
                    ERR_error_string(ERR_get_error(), buf);
                    std::cout << buf << "!!\n\n";

                    std::cout << RESULT << "!\n";
                    
                    RESULT = RSA_verify(NID_sha256, constStr, expectedSignature.length(), sigArr,
                        256, rsa_pubkey);
                    char buff[512];
                    ERR_error_string(ERR_get_error(), buff);
                    std::cout << buff << "!!\n\n";

                    EVP_PKEY_free(pkey);

                    BIO_free(bio_mem);
                    X509_free(x509);


                    std::cout << RESULT << "!\n";

                    std::cout << "\n------    END   ------\n\n";
                }
                else
                {
                    std::cout << "error code: " << ress.error() << std::endl;
                    auto result = paypal.get_openssl_verify_result();
                    if (result)
                    {
                        std::cout << "verify error: " << X509_verify_cert_error_string(result) << std::endl;
                    }
                }
                std::cout << "\n\n\n";
                paypal.stop();
            }
        }
        else
        {
            std::cout << "Header not found!\n\n";
        }
        });
    svr->Post("/", [&](const auto& req, auto& res) {
        auto size = req.files.size();
        auto ret = req.has_file("name1");
        const auto& file = req.get_file_value("name1");
        // file.filename;
        // file.content_type;
        // file.content;
        std::cout << "Posted!!";
        });
    svr->set_error_handler([](const HTTP::Request& /*req*/, HTTP::Response& res) {
        const char* fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), fmt, res.status);
        res.set_content(buf, "text/html");
        });

    svr->set_logger([](const HTTP::Request& req, const HTTP::Response& res) {
        
        });
    

    int port = 443;
    std::string ip = "0.0.0.0";
    std::cout << "Now listening on " << ip << ":" << std::to_string(port) << "\n";
    svr->listen(ip.c_str(), port);
    return 1;
}
void generate_table(uint32_t(&table)[256])
{
    uint32_t polynomial = 0xEDB88320;
    for (uint32_t i = 0; i < 256; i++)
    {
        uint32_t c = i;
        for (size_t j = 0; j < 8; j++)
        {
            if (c & 1) {
                c = polynomial ^ (c >> 1);
            }
            else {
                c >>= 1;
            }
        }
        table[i] = c;
    }
}


int main(void) 
{
    generate_table(table);
   
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