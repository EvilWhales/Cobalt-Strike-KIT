
hack:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <free@plt-0x10>:
    1020:	ff 35 3a 2f 00 00    	push   QWORD PTR [rip+0x2f3a]        # 3f60 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 3c 2f 00 00    	jmp    QWORD PTR [rip+0x2f3c]        # 3f68 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000001030 <free@plt>:
    1030:	ff 25 3a 2f 00 00    	jmp    QWORD PTR [rip+0x2f3a]        # 3f70 <free@GLIBC_2.2.5>
    1036:	68 00 00 00 00       	push   0x0
    103b:	e9 e0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001040 <strcpy@plt>:
    1040:	ff 25 32 2f 00 00    	jmp    QWORD PTR [rip+0x2f32]        # 3f78 <strcpy@GLIBC_2.2.5>
    1046:	68 01 00 00 00       	push   0x1
    104b:	e9 d0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001050 <puts@plt>:
    1050:	ff 25 2a 2f 00 00    	jmp    QWORD PTR [rip+0x2f2a]        # 3f80 <puts@GLIBC_2.2.5>
    1056:	68 02 00 00 00       	push   0x2
    105b:	e9 c0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001060 <qsort@plt>:
    1060:	ff 25 22 2f 00 00    	jmp    QWORD PTR [rip+0x2f22]        # 3f88 <qsort@GLIBC_2.2.5>
    1066:	68 03 00 00 00       	push   0x3
    106b:	e9 b0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001070 <__stack_chk_fail@plt>:
    1070:	ff 25 1a 2f 00 00    	jmp    QWORD PTR [rip+0x2f1a]        # 3f90 <__stack_chk_fail@GLIBC_2.4>
    1076:	68 04 00 00 00       	push   0x4
    107b:	e9 a0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001080 <srand@plt>:
    1080:	ff 25 12 2f 00 00    	jmp    QWORD PTR [rip+0x2f12]        # 3f98 <srand@GLIBC_2.2.5>
    1086:	68 05 00 00 00       	push   0x5
    108b:	e9 90 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001090 <calloc@plt>:
    1090:	ff 25 0a 2f 00 00    	jmp    QWORD PTR [rip+0x2f0a]        # 3fa0 <calloc@GLIBC_2.2.5>
    1096:	68 06 00 00 00       	push   0x6
    109b:	e9 80 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010a0 <strtol@plt>:
    10a0:	ff 25 02 2f 00 00    	jmp    QWORD PTR [rip+0x2f02]        # 3fa8 <strtol@GLIBC_2.2.5>
    10a6:	68 07 00 00 00       	push   0x7
    10ab:	e9 70 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010b0 <time@plt>:
    10b0:	ff 25 fa 2e 00 00    	jmp    QWORD PTR [rip+0x2efa]        # 3fb0 <time@GLIBC_2.2.5>
    10b6:	68 08 00 00 00       	push   0x8
    10bb:	e9 60 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010c0 <malloc@plt>:
    10c0:	ff 25 f2 2e 00 00    	jmp    QWORD PTR [rip+0x2ef2]        # 3fb8 <malloc@GLIBC_2.2.5>
    10c6:	68 09 00 00 00       	push   0x9
    10cb:	e9 50 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010d0 <__printf_chk@plt>:
    10d0:	ff 25 ea 2e 00 00    	jmp    QWORD PTR [rip+0x2eea]        # 3fc0 <__printf_chk@GLIBC_2.3.4>
    10d6:	68 0a 00 00 00       	push   0xa
    10db:	e9 40 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010e0 <exit@plt>:
    10e0:	ff 25 e2 2e 00 00    	jmp    QWORD PTR [rip+0x2ee2]        # 3fc8 <exit@GLIBC_2.2.5>
    10e6:	68 0b 00 00 00       	push   0xb
    10eb:	e9 30 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010f0 <rand@plt>:
    10f0:	ff 25 da 2e 00 00    	jmp    QWORD PTR [rip+0x2eda]        # 3fd0 <rand@GLIBC_2.2.5>
    10f6:	68 0c 00 00 00       	push   0xc
    10fb:	e9 20 ff ff ff       	jmp    1020 <_init+0x20>

Disassembly of section .plt.got:

0000000000001100 <__cxa_finalize@plt>:
    1100:	ff 25 f2 2e 00 00    	jmp    QWORD PTR [rip+0x2ef2]        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1106:	66 90                	xchg   ax,ax

Disassembly of section .text:

0000000000001110 <main>:
    1110:	f3 0f 1e fa          	endbr64 
    1114:	55                   	push   rbp
    1115:	48 89 f5             	mov    rbp,rsi
    1118:	53                   	push   rbx
    1119:	89 fb                	mov    ebx,edi
    111b:	31 ff                	xor    edi,edi
    111d:	48 83 ec 08          	sub    rsp,0x8
    1121:	e8 8a ff ff ff       	call   10b0 <time@plt>
    1126:	89 c7                	mov    edi,eax
    1128:	e8 53 ff ff ff       	call   1080 <srand@plt>
    112d:	83 fb 01             	cmp    ebx,0x1
    1130:	7e 46                	jle    1178 <main+0x68>
    1132:	48 8b 7d 08          	mov    rdi,QWORD PTR [rbp+0x8]
    1136:	ba 0a 00 00 00       	mov    edx,0xa
    113b:	31 f6                	xor    esi,esi
    113d:	e8 5e ff ff ff       	call   10a0 <strtol@plt>
    1142:	89 c7                	mov    edi,eax
    1144:	e8 77 01 00 00       	call   12c0 <crack_password>
    1149:	48 89 c5             	mov    rbp,rax
    114c:	48 85 c0             	test   rax,rax
    114f:	74 5d                	je     11ae <main+0x9e>
    1151:	48 89 c2             	mov    rdx,rax
    1154:	bf 01 00 00 00       	mov    edi,0x1
    1159:	48 8d 35 5d 0f 00 00 	lea    rsi,[rip+0xf5d]        # 20bd <_IO_stdin_used+0xbd>
    1160:	31 c0                	xor    eax,eax
    1162:	e8 69 ff ff ff       	call   10d0 <__printf_chk@plt>
    1167:	48 89 ef             	mov    rdi,rbp
    116a:	e8 c1 fe ff ff       	call   1030 <free@plt>
    116f:	48 83 c4 08          	add    rsp,0x8
    1173:	31 c0                	xor    eax,eax
    1175:	5b                   	pop    rbx
    1176:	5d                   	pop    rbp
    1177:	c3                   	ret    
    1178:	ba 00 04 00 00       	mov    edx,0x400
    117d:	48 8d 35 0e 0f 00 00 	lea    rsi,[rip+0xf0e]        # 2092 <_IO_stdin_used+0x92>
    1184:	bf 01 00 00 00       	mov    edi,0x1
    1189:	31 c0                	xor    eax,eax
    118b:	e8 40 ff ff ff       	call   10d0 <__printf_chk@plt>
    1190:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
    1194:	bf 01 00 00 00       	mov    edi,0x1
    1199:	31 c0                	xor    eax,eax
    119b:	48 8d 35 be 0e 00 00 	lea    rsi,[rip+0xebe]        # 2060 <_IO_stdin_used+0x60>
    11a2:	e8 29 ff ff ff       	call   10d0 <__printf_chk@plt>
    11a7:	bf 00 04 00 00       	mov    edi,0x400
    11ac:	eb 96                	jmp    1144 <main+0x34>
    11ae:	48 8d 3d f7 0e 00 00 	lea    rdi,[rip+0xef7]        # 20ac <_IO_stdin_used+0xac>
    11b5:	e8 96 fe ff ff       	call   1050 <puts@plt>
    11ba:	eb b3                	jmp    116f <main+0x5f>
    11bc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000000011c0 <_start>:
    11c0:	f3 0f 1e fa          	endbr64 
    11c4:	31 ed                	xor    ebp,ebp
    11c6:	49 89 d1             	mov    r9,rdx
    11c9:	5e                   	pop    rsi
    11ca:	48 89 e2             	mov    rdx,rsp
    11cd:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    11d1:	50                   	push   rax
    11d2:	54                   	push   rsp
    11d3:	45 31 c0             	xor    r8d,r8d
    11d6:	31 c9                	xor    ecx,ecx
    11d8:	48 8d 3d 31 ff ff ff 	lea    rdi,[rip+0xffffffffffffff31]        # 1110 <main>
    11df:	ff 15 f3 2d 00 00    	call   QWORD PTR [rip+0x2df3]        # 3fd8 <__libc_start_main@GLIBC_2.34>
    11e5:	f4                   	hlt    
    11e6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    11ed:	00 00 00 

00000000000011f0 <deregister_tm_clones>:
    11f0:	48 8d 3d 19 2e 00 00 	lea    rdi,[rip+0x2e19]        # 4010 <__TMC_END__>
    11f7:	48 8d 05 12 2e 00 00 	lea    rax,[rip+0x2e12]        # 4010 <__TMC_END__>
    11fe:	48 39 f8             	cmp    rax,rdi
    1201:	74 15                	je     1218 <deregister_tm_clones+0x28>
    1203:	48 8b 05 d6 2d 00 00 	mov    rax,QWORD PTR [rip+0x2dd6]        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    120a:	48 85 c0             	test   rax,rax
    120d:	74 09                	je     1218 <deregister_tm_clones+0x28>
    120f:	ff e0                	jmp    rax
    1211:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1218:	c3                   	ret    
    1219:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001220 <register_tm_clones>:
    1220:	48 8d 3d e9 2d 00 00 	lea    rdi,[rip+0x2de9]        # 4010 <__TMC_END__>
    1227:	48 8d 35 e2 2d 00 00 	lea    rsi,[rip+0x2de2]        # 4010 <__TMC_END__>
    122e:	48 29 fe             	sub    rsi,rdi
    1231:	48 89 f0             	mov    rax,rsi
    1234:	48 c1 ee 3f          	shr    rsi,0x3f
    1238:	48 c1 f8 03          	sar    rax,0x3
    123c:	48 01 c6             	add    rsi,rax
    123f:	48 d1 fe             	sar    rsi,1
    1242:	74 14                	je     1258 <register_tm_clones+0x38>
    1244:	48 8b 05 a5 2d 00 00 	mov    rax,QWORD PTR [rip+0x2da5]        # 3ff0 <_ITM_registerTMCloneTable@Base>
    124b:	48 85 c0             	test   rax,rax
    124e:	74 08                	je     1258 <register_tm_clones+0x38>
    1250:	ff e0                	jmp    rax
    1252:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1258:	c3                   	ret    
    1259:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001260 <__do_global_dtors_aux>:
    1260:	f3 0f 1e fa          	endbr64 
    1264:	80 3d a5 2d 00 00 00 	cmp    BYTE PTR [rip+0x2da5],0x0        # 4010 <__TMC_END__>
    126b:	75 2b                	jne    1298 <__do_global_dtors_aux+0x38>
    126d:	55                   	push   rbp
    126e:	48 83 3d 82 2d 00 00 	cmp    QWORD PTR [rip+0x2d82],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1275:	00 
    1276:	48 89 e5             	mov    rbp,rsp
    1279:	74 0c                	je     1287 <__do_global_dtors_aux+0x27>
    127b:	48 8b 3d 86 2d 00 00 	mov    rdi,QWORD PTR [rip+0x2d86]        # 4008 <__dso_handle>
    1282:	e8 79 fe ff ff       	call   1100 <__cxa_finalize@plt>
    1287:	e8 64 ff ff ff       	call   11f0 <deregister_tm_clones>
    128c:	c6 05 7d 2d 00 00 01 	mov    BYTE PTR [rip+0x2d7d],0x1        # 4010 <__TMC_END__>
    1293:	5d                   	pop    rbp
    1294:	c3                   	ret    
    1295:	0f 1f 00             	nop    DWORD PTR [rax]
    1298:	c3                   	ret    
    1299:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000012a0 <frame_dummy>:
    12a0:	f3 0f 1e fa          	endbr64 
    12a4:	e9 77 ff ff ff       	jmp    1220 <register_tm_clones>
    12a9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000012b0 <sort_cmp>:
    12b0:	f3 0f 1e fa          	endbr64 
    12b4:	48 8b 07             	mov    rax,QWORD PTR [rdi]
    12b7:	2b 06                	sub    eax,DWORD PTR [rsi]
    12b9:	c3                   	ret    
    12ba:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000000012c0 <crack_password>:
    12c0:	f3 0f 1e fa          	endbr64 
    12c4:	55                   	push   rbp
    12c5:	be 01 00 00 00       	mov    esi,0x1
    12ca:	48 89 e5             	mov    rbp,rsp
    12cd:	41 57                	push   r15
    12cf:	41 56                	push   r14
    12d1:	41 55                	push   r13
    12d3:	41 54                	push   r12
    12d5:	53                   	push   rbx
    12d6:	48 81 ec 68 01 00 00 	sub    rsp,0x168
    12dd:	89 bd a4 fe ff ff    	mov    DWORD PTR [rbp-0x15c],edi
    12e3:	bf 40 00 00 00       	mov    edi,0x40
    12e8:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    12ef:	00 00 
    12f1:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
    12f5:	31 c0                	xor    eax,eax
    12f7:	e8 94 fd ff ff       	call   1090 <calloc@plt>
    12fc:	48 89 85 b0 fe ff ff 	mov    QWORD PTR [rbp-0x150],rax
    1303:	48 85 c0             	test   rax,rax
    1306:	0f 84 70 04 00 00    	je     177c <crack_password+0x4bc>
    130c:	48 89 e0             	mov    rax,rsp
    130f:	48 39 c4             	cmp    rsp,rax
    1312:	74 15                	je     1329 <crack_password+0x69>
    1314:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    131b:	48 83 8c 24 f8 0f 00 	or     QWORD PTR [rsp+0xff8],0x0
    1322:	00 00 
    1324:	48 39 c4             	cmp    rsp,rax
    1327:	75 eb                	jne    1314 <crack_password+0x54>
    1329:	48 81 ec 00 03 00 00 	sub    rsp,0x300
    1330:	48 83 8c 24 f8 02 00 	or     QWORD PTR [rsp+0x2f8],0x0
    1337:	00 00 
    1339:	45 31 ed             	xor    r13d,r13d
    133c:	48 63 85 a4 fe ff ff 	movsxd rax,DWORD PTR [rbp-0x15c]
    1343:	4c 8d 24 85 00 00 00 	lea    r12,[rax*4+0x0]
    134a:	00 
    134b:	48 89 85 70 fe ff ff 	mov    QWORD PTR [rbp-0x190],rax
    1352:	49 89 e7             	mov    r15,rsp
    1355:	0f 1f 00             	nop    DWORD PTR [rax]
    1358:	4c 89 e7             	mov    rdi,r12
    135b:	e8 60 fd ff ff       	call   10c0 <malloc@plt>
    1360:	4b 89 04 ef          	mov    QWORD PTR [r15+r13*8],rax
    1364:	48 85 c0             	test   rax,rax
    1367:	0f 84 e4 03 00 00    	je     1751 <crack_password+0x491>
    136d:	49 83 c5 01          	add    r13,0x1
    1371:	49 83 fd 5f          	cmp    r13,0x5f
    1375:	75 e1                	jne    1358 <crack_password+0x98>
    1377:	48 89 e0             	mov    rax,rsp
    137a:	48 39 c4             	cmp    rsp,rax
    137d:	74 15                	je     1394 <crack_password+0xd4>
    137f:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    1386:	48 83 8c 24 f8 0f 00 	or     QWORD PTR [rsp+0xff8],0x0
    138d:	00 00 
    138f:	48 39 c4             	cmp    rsp,rax
    1392:	75 eb                	jne    137f <crack_password+0xbf>
    1394:	48 81 ec 80 01 00 00 	sub    rsp,0x180
    139b:	48 83 8c 24 78 01 00 	or     QWORD PTR [rsp+0x178],0x0
    13a2:	00 00 
    13a4:	66 0f 6f 05 24 0d 00 	movdqa xmm0,XMMWORD PTR [rip+0xd24]        # 20d0 <_IO_stdin_used+0xd0>
    13ab:	00 
    13ac:	48 8b 05 6d 0d 00 00 	mov    rax,QWORD PTR [rip+0xd6d]        # 2120 <_IO_stdin_used+0x120>
    13b3:	ba 7c 7d 00 00       	mov    edx,0x7d7c
    13b8:	48 8d 35 49 0c 00 00 	lea    rsi,[rip+0xc49]        # 2008 <_IO_stdin_used+0x8>
    13bf:	bf 01 00 00 00       	mov    edi,0x1
    13c4:	8b 9d a4 fe ff ff    	mov    ebx,DWORD PTR [rbp-0x15c]
    13ca:	0f 29 85 e0 fe ff ff 	movaps XMMWORD PTR [rbp-0x120],xmm0
    13d1:	66 0f 6f 05 07 0d 00 	movdqa xmm0,XMMWORD PTR [rip+0xd07]        # 20e0 <_IO_stdin_used+0xe0>
    13d8:	00 
    13d9:	4c 8d b5 3f ff ff ff 	lea    r14,[rbp-0xc1]
    13e0:	48 89 85 30 ff ff ff 	mov    QWORD PTR [rbp-0xd0],rax
    13e7:	31 c0                	xor    eax,eax
    13e9:	0f 29 85 f0 fe ff ff 	movaps XMMWORD PTR [rbp-0x110],xmm0
    13f0:	66 0f 6f 05 f8 0c 00 	movdqa xmm0,XMMWORD PTR [rip+0xcf8]        # 20f0 <_IO_stdin_used+0xf0>
    13f7:	00 
    13f8:	66 89 95 3c ff ff ff 	mov    WORD PTR [rbp-0xc4],dx
    13ff:	89 da                	mov    edx,ebx
    1401:	0f 29 85 00 ff ff ff 	movaps XMMWORD PTR [rbp-0x100],xmm0
    1408:	66 0f 6f 05 f0 0c 00 	movdqa xmm0,XMMWORD PTR [rip+0xcf0]        # 2100 <_IO_stdin_used+0x100>
    140f:	00 
    1410:	48 89 a5 b8 fe ff ff 	mov    QWORD PTR [rbp-0x148],rsp
    1417:	0f 29 85 10 ff ff ff 	movaps XMMWORD PTR [rbp-0xf0],xmm0
    141e:	66 0f 6f 05 ea 0c 00 	movdqa xmm0,XMMWORD PTR [rip+0xcea]        # 2110 <_IO_stdin_used+0x110>
    1425:	00 
    1426:	c7 85 38 ff ff ff 78 	mov    DWORD PTR [rbp-0xc8],0x7b7a7978
    142d:	79 7a 7b 
    1430:	c6 85 3e ff ff ff 7e 	mov    BYTE PTR [rbp-0xc2],0x7e
    1437:	0f 29 85 20 ff ff ff 	movaps XMMWORD PTR [rbp-0xe0],xmm0
    143e:	e8 8d fc ff ff       	call   10d0 <__printf_chk@plt>
    1443:	89 d8                	mov    eax,ebx
    1445:	4c 89 bd d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],r15
    144c:	4d 89 f7             	mov    r15,r14
    144f:	48 c7 85 a8 fe ff ff 	mov    QWORD PTR [rbp-0x158],0x0
    1456:	00 00 00 00 
    145a:	d1 f8                	sar    eax,1
    145c:	48 98                	cdqe   
    145e:	48 c1 e0 02          	shl    rax,0x2
    1462:	48 89 85 80 fe ff ff 	mov    QWORD PTR [rbp-0x180],rax
    1469:	8d 43 ff             	lea    eax,[rbx-0x1]
    146c:	48 8d 04 85 04 00 00 	lea    rax,[rax*4+0x4]
    1473:	00 
    1474:	48 89 85 78 fe ff ff 	mov    QWORD PTR [rbp-0x188],rax
    147b:	48 8d 85 e0 fe ff ff 	lea    rax,[rbp-0x120]
    1482:	48 89 85 88 fe ff ff 	mov    QWORD PTR [rbp-0x178],rax
    1489:	48 8b 85 a8 fe ff ff 	mov    rax,QWORD PTR [rbp-0x158]
    1490:	48 c7 85 c8 fe ff ff 	mov    QWORD PTR [rbp-0x138],0x0
    1497:	00 00 00 00 
    149b:	48 83 c0 01          	add    rax,0x1
    149f:	48 89 85 98 fe ff ff 	mov    QWORD PTR [rbp-0x168],rax
    14a6:	48 8d 85 40 ff ff ff 	lea    rax,[rbp-0xc0]
    14ad:	48 89 85 90 fe ff ff 	mov    QWORD PTR [rbp-0x170],rax
    14b4:	8b 85 a4 fe ff ff    	mov    eax,DWORD PTR [rbp-0x15c]
    14ba:	85 c0                	test   eax,eax
    14bc:	0f 8e 7c 01 00 00    	jle    163e <crack_password+0x37e>
    14c2:	48 8b 9d 88 fe ff ff 	mov    rbx,QWORD PTR [rbp-0x178]
    14c9:	49 89 de             	mov    r14,rbx
    14cc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    14d0:	e8 1b fc ff ff       	call   10f0 <rand@plt>
    14d5:	48 83 c3 01          	add    rbx,0x1
    14d9:	48 63 d0             	movsxd rdx,eax
    14dc:	89 c1                	mov    ecx,eax
    14de:	48 69 d2 85 91 76 ac 	imul   rdx,rdx,0xffffffffac769185
    14e5:	c1 f9 1f             	sar    ecx,0x1f
    14e8:	48 c1 ea 20          	shr    rdx,0x20
    14ec:	01 c2                	add    edx,eax
    14ee:	c1 fa 06             	sar    edx,0x6
    14f1:	29 ca                	sub    edx,ecx
    14f3:	6b ca 5f             	imul   ecx,edx,0x5f
    14f6:	29 c8                	sub    eax,ecx
    14f8:	48 63 d0             	movsxd rdx,eax
    14fb:	0f b6 43 ff          	movzx  eax,BYTE PTR [rbx-0x1]
    14ff:	0f b6 8c 15 e0 fe ff 	movzx  ecx,BYTE PTR [rbp+rdx*1-0x120]
    1506:	ff 
    1507:	88 4b ff             	mov    BYTE PTR [rbx-0x1],cl
    150a:	88 84 15 e0 fe ff ff 	mov    BYTE PTR [rbp+rdx*1-0x120],al
    1511:	49 39 df             	cmp    r15,rbx
    1514:	75 ba                	jne    14d0 <crack_password+0x210>
    1516:	e8 d5 fb ff ff       	call   10f0 <rand@plt>
    151b:	48 8b b5 90 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x170]
    1522:	83 e0 3f             	and    eax,0x3f
    1525:	4c 8d 24 06          	lea    r12,[rsi+rax*1]
    1529:	48 8b b5 b0 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x150]
    1530:	4c 89 e7             	mov    rdi,r12
    1533:	e8 08 fb ff ff       	call   1040 <strcpy@plt>
    1538:	48 8b 85 98 fe ff ff 	mov    rax,QWORD PTR [rbp-0x168]
    153f:	4c 89 bd c0 fe ff ff 	mov    QWORD PTR [rbp-0x140],r15
    1546:	41 c6 04 04 00       	mov    BYTE PTR [r12+rax*1],0x0
    154b:	48 8b 85 a8 fe ff ff 	mov    rax,QWORD PTR [rbp-0x158]
    1552:	4c 01 e0             	add    rax,r12
    1555:	48 89 85 d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],rax
    155c:	eb 35                	jmp    1593 <crack_password+0x2d3>
    155e:	66 90                	xchg   ax,ax
    1560:	31 c0                	xor    eax,eax
    1562:	48 63 db             	movsxd rbx,ebx
    1565:	49 83 c6 01          	add    r14,0x1
    1569:	e8 1d 02 00 00       	call   178b <cpu_clock>
    156e:	48 8b b5 d0 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x130]
    1575:	44 29 e8             	sub    eax,r13d
    1578:	48 8b 14 de          	mov    rdx,QWORD PTR [rsi+rbx*8]
    157c:	48 8b b5 c8 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x138]
    1583:	89 04 32             	mov    DWORD PTR [rdx+rsi*1],eax
    1586:	4c 39 b5 c0 fe ff ff 	cmp    QWORD PTR [rbp-0x140],r14
    158d:	0f 84 88 00 00 00    	je     161b <crack_password+0x35b>
    1593:	41 0f be 1e          	movsx  ebx,BYTE PTR [r14]
    1597:	48 8b 85 d8 fe ff ff 	mov    rax,QWORD PTR [rbp-0x128]
    159e:	41 89 df             	mov    r15d,ebx
    15a1:	83 eb 20             	sub    ebx,0x20
    15a4:	44 88 38             	mov    BYTE PTR [rax],r15b
    15a7:	31 c0                	xor    eax,eax
    15a9:	e8 dd 01 00 00       	call   178b <cpu_clock>
    15ae:	4c 89 e7             	mov    rdi,r12
    15b1:	49 89 c5             	mov    r13,rax
    15b4:	e8 e7 01 00 00       	call   17a0 <check_password>
    15b9:	85 c0                	test   eax,eax
    15bb:	74 a3                	je     1560 <crack_password+0x2a0>
    15bd:	44 89 fb             	mov    ebx,r15d
    15c0:	4c 8b bd d0 fe ff ff 	mov    r15,QWORD PTR [rbp-0x130]
    15c7:	4d 8d a7 f8 02 00 00 	lea    r12,[r15+0x2f8]
    15ce:	66 90                	xchg   ax,ax
    15d0:	49 8b 3f             	mov    rdi,QWORD PTR [r15]
    15d3:	49 83 c7 08          	add    r15,0x8
    15d7:	e8 54 fa ff ff       	call   1030 <free@plt>
    15dc:	4d 39 e7             	cmp    r15,r12
    15df:	75 ef                	jne    15d0 <crack_password+0x310>
    15e1:	48 8b 85 b0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x150]
    15e8:	48 8b b5 a8 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x158]
    15ef:	88 1c 30             	mov    BYTE PTR [rax+rsi*1],bl
    15f2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    15f6:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    15fd:	00 00 
    15ff:	0f 85 81 01 00 00    	jne    1786 <crack_password+0x4c6>
    1605:	48 8b 85 b0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x150]
    160c:	48 8d 65 d8          	lea    rsp,[rbp-0x28]
    1610:	5b                   	pop    rbx
    1611:	41 5c                	pop    r12
    1613:	41 5d                	pop    r13
    1615:	41 5e                	pop    r14
    1617:	41 5f                	pop    r15
    1619:	5d                   	pop    rbp
    161a:	c3                   	ret    
    161b:	48 83 85 c8 fe ff ff 	add    QWORD PTR [rbp-0x138],0x4
    1622:	04 
    1623:	4c 8b bd c0 fe ff ff 	mov    r15,QWORD PTR [rbp-0x140]
    162a:	48 8b 85 c8 fe ff ff 	mov    rax,QWORD PTR [rbp-0x138]
    1631:	48 3b 85 78 fe ff ff 	cmp    rax,QWORD PTR [rbp-0x188]
    1638:	0f 85 84 fe ff ff    	jne    14c2 <crack_password+0x202>
    163e:	31 db                	xor    ebx,ebx
    1640:	4c 8b a5 70 fe ff ff 	mov    r12,QWORD PTR [rbp-0x190]
    1647:	4c 8b ad 80 fe ff ff 	mov    r13,QWORD PTR [rbp-0x180]
    164e:	4c 89 bd d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],r15
    1655:	4c 8b b5 d0 fe ff ff 	mov    r14,QWORD PTR [rbp-0x130]
    165c:	49 89 df             	mov    r15,rbx
    165f:	90                   	nop
    1660:	4b 8b 1c fe          	mov    rbx,QWORD PTR [r14+r15*8]
    1664:	ba 04 00 00 00       	mov    edx,0x4
    1669:	48 8d 0d 40 fc ff ff 	lea    rcx,[rip+0xfffffffffffffc40]        # 12b0 <sort_cmp>
    1670:	4c 89 e6             	mov    rsi,r12
    1673:	48 89 df             	mov    rdi,rbx
    1676:	e8 e5 f9 ff ff       	call   1060 <qsort@plt>
    167b:	42 8b 14 2b          	mov    edx,DWORD PTR [rbx+r13*1]
    167f:	48 8b 85 b8 fe ff ff 	mov    rax,QWORD PTR [rbp-0x148]
    1686:	42 89 14 b8          	mov    DWORD PTR [rax+r15*4],edx
    168a:	49 83 c7 01          	add    r15,0x1
    168e:	49 83 ff 5f          	cmp    r15,0x5f
    1692:	75 cc                	jne    1660 <crack_password+0x3a0>
    1694:	4c 8b bd d8 fe ff ff 	mov    r15,QWORD PTR [rbp-0x128]
    169b:	0f b6 bd a3 fe ff ff 	movzx  edi,BYTE PTR [rbp-0x15d]
    16a2:	48 89 c6             	mov    rsi,rax
    16a5:	31 c9                	xor    ecx,ecx
    16a7:	b8 20 00 00 00       	mov    eax,0x20
    16ac:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    16b0:	8b 54 86 80          	mov    edx,DWORD PTR [rsi+rax*4-0x80]
    16b4:	39 ca                	cmp    edx,ecx
    16b6:	7e 04                	jle    16bc <crack_password+0x3fc>
    16b8:	89 c7                	mov    edi,eax
    16ba:	89 d1                	mov    ecx,edx
    16bc:	48 83 c0 01          	add    rax,0x1
    16c0:	48 83 f8 7f          	cmp    rax,0x7f
    16c4:	75 ea                	jne    16b0 <crack_password+0x3f0>
    16c6:	48 8b 85 b0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x150]
    16cd:	48 8b b5 a8 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x158]
    16d4:	40 88 bd a3 fe ff ff 	mov    BYTE PTR [rbp-0x15d],dil
    16db:	40 88 3c 30          	mov    BYTE PTR [rax+rsi*1],dil
    16df:	48 89 c2             	mov    rdx,rax
    16e2:	bf 01 00 00 00       	mov    edi,0x1
    16e7:	31 c0                	xor    eax,eax
    16e9:	48 8d 35 48 09 00 00 	lea    rsi,[rip+0x948]        # 2038 <_IO_stdin_used+0x38>
    16f0:	e8 db f9 ff ff       	call   10d0 <__printf_chk@plt>
    16f5:	48 8b 85 98 fe ff ff 	mov    rax,QWORD PTR [rbp-0x168]
    16fc:	48 89 85 a8 fe ff ff 	mov    QWORD PTR [rbp-0x158],rax
    1703:	48 83 f8 3f          	cmp    rax,0x3f
    1707:	0f 85 7c fd ff ff    	jne    1489 <crack_password+0x1c9>
    170d:	4c 8b bd d0 fe ff ff 	mov    r15,QWORD PTR [rbp-0x130]
    1714:	48 8b bd b0 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x150]
    171b:	e8 10 f9 ff ff       	call   1030 <free@plt>
    1720:	4c 89 fb             	mov    rbx,r15
    1723:	4d 8d a7 f8 02 00 00 	lea    r12,[r15+0x2f8]
    172a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1730:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
    1733:	48 83 c3 08          	add    rbx,0x8
    1737:	e8 f4 f8 ff ff       	call   1030 <free@plt>
    173c:	4c 39 e3             	cmp    rbx,r12
    173f:	75 ef                	jne    1730 <crack_password+0x470>
    1741:	48 c7 85 b0 fe ff ff 	mov    QWORD PTR [rbp-0x150],0x0
    1748:	00 00 00 00 
    174c:	e9 a1 fe ff ff       	jmp    15f2 <crack_password+0x332>
    1751:	45 85 ed             	test   r13d,r13d
    1754:	74 1a                	je     1770 <crack_password+0x4b0>
    1756:	41 8d 45 ff          	lea    eax,[r13-0x1]
    175a:	49 8d 5c c7 08       	lea    rbx,[r15+rax*8+0x8]
    175f:	49 8b 3f             	mov    rdi,QWORD PTR [r15]
    1762:	49 83 c7 08          	add    r15,0x8
    1766:	e8 c5 f8 ff ff       	call   1030 <free@plt>
    176b:	4c 39 fb             	cmp    rbx,r15
    176e:	75 ef                	jne    175f <crack_password+0x49f>
    1770:	48 8b bd b0 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x150]
    1777:	e8 b4 f8 ff ff       	call   1030 <free@plt>
    177c:	bf 01 00 00 00       	mov    edi,0x1
    1781:	e8 5a f9 ff ff       	call   10e0 <exit@plt>
    1786:	e8 e5 f8 ff ff       	call   1070 <__stack_chk_fail@plt>

000000000000178b <cpu_clock>:
    178b:	0f 31                	rdtsc  
    178d:	48 c1 e2 20          	shl    rdx,0x20
    1791:	48 09 d0             	or     rax,rdx
    1794:	c3                   	ret    
    1795:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    179c:	00 00 00 
    179f:	90                   	nop

00000000000017a0 <check_password>:
    17a0:	f3 0f 1e fa          	endbr64 
    17a4:	0f b6 07             	movzx  eax,BYTE PTR [rdi]
    17a7:	84 c0                	test   al,al
    17a9:	74 30                	je     17db <check_password+0x3b>
    17ab:	48 8d 0d 76 09 00 00 	lea    rcx,[rip+0x976]        # 2128 <_IO_stdin_used+0x128>
    17b2:	ba 6f 00 00 00       	mov    edx,0x6f
    17b7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    17be:	00 00 
    17c0:	38 c2                	cmp    dl,al
    17c2:	75 17                	jne    17db <check_password+0x3b>
    17c4:	0f b6 47 01          	movzx  eax,BYTE PTR [rdi+0x1]
    17c8:	48 83 c7 01          	add    rdi,0x1
    17cc:	48 83 c1 01          	add    rcx,0x1
    17d0:	0f b6 11             	movzx  edx,BYTE PTR [rcx]
    17d3:	84 c0                	test   al,al
    17d5:	74 09                	je     17e0 <check_password+0x40>
    17d7:	84 d2                	test   dl,dl
    17d9:	75 e5                	jne    17c0 <check_password+0x20>
    17db:	31 c0                	xor    eax,eax
    17dd:	c3                   	ret    
    17de:	66 90                	xchg   ax,ax
    17e0:	31 c0                	xor    eax,eax
    17e2:	84 d2                	test   dl,dl
    17e4:	0f 94 c0             	sete   al
    17e7:	c3                   	ret    

Disassembly of section .fini:

00000000000017e8 <_fini>:
    17e8:	f3 0f 1e fa          	endbr64 
    17ec:	48 83 ec 08          	sub    rsp,0x8
    17f0:	48 83 c4 08          	add    rsp,0x8
    17f4:	c3                   	ret    
