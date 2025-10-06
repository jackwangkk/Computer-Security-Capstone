#include <iostream>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <string>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

unsigned int long_secure_random(time_t seed)
{
    srand(seed);
    vector<unsigned int> r(100);
    for (int i = 0; i < 100; i++)
    {
        r[i] = rand() % 32323;
    }
    for (int i = 1; i < 100; i++)
    {
        r[i] = r[i] * r[i - 1] * r[i - 1] * r[i - 1] +
               r[i] * r[i - 1] * r[i - 1] * 3 +
               r[i] * r[i - 1] * 2 +
               r[i];
    }
    return r[99];
}

bool try_guess(const string &host, int port, const string &guess)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        cerr << "[-] Failed to create socket" << endl;
        return false;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0)
    {
        cerr << "[-] Invalid address/ Address not supported" << endl;
        close(sock);
        return false;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        cerr << "[-] Connection failed" << endl;
        close(sock);
        return false;
    }

    string message = guess + "\n";
    send(sock, message.c_str(), message.size(), 0);

    char buffer[1024] = {0};
    int valread = read(sock, buffer, sizeof(buffer) - 1);
    close(sock);

    if (valread > 0)
    {
        string response(buffer);
        cout << response << endl;
        if (response.find("CSC2025") != string::npos)
        {
            cout << "[!!!] Flag found!" << endl;
            return true;
        }
    }
    return false;
}

int main()
{
    string host = "140.113.207.245";
    int port = 30171;

    time_t now = time(nullptr);

    for (int offset = -5; offset <= 5; offset++)
    {
        time_t t = now + offset;
        unsigned int guess = long_secure_random(t);
        cout << "[+] Trying time=" << t << " guess=" << guess << endl;

        if (try_guess(host, port, to_string(guess)))
        {
            break;
        }
    }

    return 0;
}