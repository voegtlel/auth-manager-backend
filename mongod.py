import os
import subprocess

if __name__ == '__main__':
    os.chdir(os.path.join(os.path.dirname(__file__), 'mongo'))
    os.makedirs('data', exist_ok=True)
    subprocess.Popen(['mongod.exe', '--dbpath', 'data']).communicate()
