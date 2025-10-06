import paramiko
import sys

def upload_file(victim_ip, username, password, local_file, remote_path):
    try:
        # 建立 SSH 連線
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(victim_ip, username=username, password=password)

        # 使用 SFTP 上傳檔案
        sftp = client.open_sftp()
        sftp.put(local_file, remote_path)
        sftp.close()

        print(f"[+] Successfully uploaded {local_file} to {remote_path}")
        client.close()
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python upload_file.py <Victim IP> <Username> <Password> <Local File>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    local_file = sys.argv[4]
    remote_path = "/app/" + local_file.split("/")[-1]

    upload_file(victim_ip, username, password, local_file, remote_path)