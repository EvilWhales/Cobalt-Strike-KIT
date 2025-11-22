
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

0000000000001080 <printf@plt>:
    1080:	ff 25 12 2f 00 00    	jmp    QWORD PTR [rip+0x2f12]        # 3f98 <printf@GLIBC_2.2.5>
    1086:	68 05 00 00 00       	push   0x5
    108b:	e9 90 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001090 <memset@plt>:
    1090:	ff 25 0a 2f 00 00    	jmp    QWORD PTR [rip+0x2f0a]        # 3fa0 <memset@GLIBC_2.2.5>
    1096:	68 06 00 00 00       	push   0x6
    109b:	e9 80 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010a0 <srand@plt>:
    10a0:	ff 25 02 2f 00 00    	jmp    QWORD PTR [rip+0x2f02]        # 3fa8 <srand@GLIBC_2.2.5>
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

00000000000010d0 <atoi@plt>:
    10d0:	ff 25 ea 2e 00 00    	jmp    QWORD PTR [rip+0x2eea]        # 3fc0 <atoi@GLIBC_2.2.5>
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

0000000000001110 <_start>:
    1110:	f3 0f 1e fa          	endbr64 
    1114:	31 ed                	xor    ebp,ebp
    1116:	49 89 d1             	mov    r9,rdx
    1119:	5e                   	pop    rsi
    111a:	48 89 e2             	mov    rdx,rsp
    111d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    1121:	50                   	push   rax
    1122:	54                   	push   rsp
    1123:	45 31 c0             	xor    r8d,r8d
    1126:	31 c9                	xor    ecx,ecx
    1128:	48 8d 3d ca 00 00 00 	lea    rdi,[rip+0xca]        # 11f9 <main>
    112f:	ff 15 a3 2e 00 00    	call   QWORD PTR [rip+0x2ea3]        # 3fd8 <__libc_start_main@GLIBC_2.34>
    1135:	f4                   	hlt    
    1136:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    113d:	00 00 00 

0000000000001140 <deregister_tm_clones>:
    1140:	48 8d 3d c9 2e 00 00 	lea    rdi,[rip+0x2ec9]        # 4010 <__TMC_END__>
    1147:	48 8d 05 c2 2e 00 00 	lea    rax,[rip+0x2ec2]        # 4010 <__TMC_END__>
    114e:	48 39 f8             	cmp    rax,rdi
    1151:	74 15                	je     1168 <deregister_tm_clones+0x28>
    1153:	48 8b 05 86 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e86]        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    115a:	48 85 c0             	test   rax,rax
    115d:	74 09                	je     1168 <deregister_tm_clones+0x28>
    115f:	ff e0                	jmp    rax
    1161:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1168:	c3                   	ret    
    1169:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001170 <register_tm_clones>:
    1170:	48 8d 3d 99 2e 00 00 	lea    rdi,[rip+0x2e99]        # 4010 <__TMC_END__>
    1177:	48 8d 35 92 2e 00 00 	lea    rsi,[rip+0x2e92]        # 4010 <__TMC_END__>
    117e:	48 29 fe             	sub    rsi,rdi
    1181:	48 89 f0             	mov    rax,rsi
    1184:	48 c1 ee 3f          	shr    rsi,0x3f
    1188:	48 c1 f8 03          	sar    rax,0x3
    118c:	48 01 c6             	add    rsi,rax
    118f:	48 d1 fe             	sar    rsi,1
    1192:	74 14                	je     11a8 <register_tm_clones+0x38>
    1194:	48 8b 05 55 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e55]        # 3ff0 <_ITM_registerTMCloneTable@Base>
    119b:	48 85 c0             	test   rax,rax
    119e:	74 08                	je     11a8 <register_tm_clones+0x38>
    11a0:	ff e0                	jmp    rax
    11a2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    11a8:	c3                   	ret    
    11a9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000011b0 <__do_global_dtors_aux>:
    11b0:	f3 0f 1e fa          	endbr64 
    11b4:	80 3d 55 2e 00 00 00 	cmp    BYTE PTR [rip+0x2e55],0x0        # 4010 <__TMC_END__>
    11bb:	75 2b                	jne    11e8 <__do_global_dtors_aux+0x38>
    11bd:	55                   	push   rbp
    11be:	48 83 3d 32 2e 00 00 	cmp    QWORD PTR [rip+0x2e32],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    11c5:	00 
    11c6:	48 89 e5             	mov    rbp,rsp
    11c9:	74 0c                	je     11d7 <__do_global_dtors_aux+0x27>
    11cb:	48 8b 3d 36 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2e36]        # 4008 <__dso_handle>
    11d2:	e8 29 ff ff ff       	call   1100 <__cxa_finalize@plt>
    11d7:	e8 64 ff ff ff       	call   1140 <deregister_tm_clones>
    11dc:	c6 05 2d 2e 00 00 01 	mov    BYTE PTR [rip+0x2e2d],0x1        # 4010 <__TMC_END__>
    11e3:	5d                   	pop    rbp
    11e4:	c3                   	ret    
    11e5:	0f 1f 00             	nop    DWORD PTR [rax]
    11e8:	c3                   	ret    
    11e9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000011f0 <frame_dummy>:
    11f0:	f3 0f 1e fa          	endbr64 
    11f4:	e9 77 ff ff ff       	jmp    1170 <register_tm_clones>

00000000000011f9 <main>:
    11f9:	f3 0f 1e fa          	endbr64 
    11fd:	55                   	push   rbp
    11fe:	48 89 e5             	mov    rbp,rsp
    1201:	48 83 ec 20          	sub    rsp,0x20
    1205:	89 7d ec             	mov    DWORD PTR [rbp-0x14],edi
    1208:	48 89 75 e0          	mov    QWORD PTR [rbp-0x20],rsi
    120c:	bf 00 00 00 00       	mov    edi,0x0
    1211:	e8 9a fe ff ff       	call   10b0 <time@plt>
    1216:	89 c7                	mov    edi,eax
    1218:	e8 83 fe ff ff       	call   10a0 <srand@plt>
    121d:	c7 45 f4 00 04 00 00 	mov    DWORD PTR [rbp-0xc],0x400
    1224:	83 7d ec 01          	cmp    DWORD PTR [rbp-0x14],0x1
    1228:	7e 18                	jle    1242 <main+0x49>
    122a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    122e:	48 83 c0 08          	add    rax,0x8
    1232:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1235:	48 89 c7             	mov    rdi,rax
    1238:	e8 93 fe ff ff       	call   10d0 <atoi@plt>
    123d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
    1240:	eb 37                	jmp    1279 <main+0x80>
    1242:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
    1245:	89 c6                	mov    esi,eax
    1247:	48 8d 05 ba 0d 00 00 	lea    rax,[rip+0xdba]        # 2008 <_IO_stdin_used+0x8>
    124e:	48 89 c7             	mov    rdi,rax
    1251:	b8 00 00 00 00       	mov    eax,0x0
    1256:	e8 25 fe ff ff       	call   1080 <printf@plt>
    125b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    125f:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1262:	48 89 c6             	mov    rsi,rax
    1265:	48 8d 05 bc 0d 00 00 	lea    rax,[rip+0xdbc]        # 2028 <_IO_stdin_used+0x28>
    126c:	48 89 c7             	mov    rdi,rax
    126f:	b8 00 00 00 00       	mov    eax,0x0
    1274:	e8 07 fe ff ff       	call   1080 <printf@plt>
    1279:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
    127c:	89 c7                	mov    edi,eax
    127e:	e8 72 00 00 00       	call   12f5 <crack_password>
    1283:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1287:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
    128c:	75 11                	jne    129f <main+0xa6>
    128e:	48 8d 05 c5 0d 00 00 	lea    rax,[rip+0xdc5]        # 205a <_IO_stdin_used+0x5a>
    1295:	48 89 c7             	mov    rdi,rax
    1298:	e8 b3 fd ff ff       	call   1050 <puts@plt>
    129d:	eb 27                	jmp    12c6 <main+0xcd>
    129f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    12a3:	48 89 c6             	mov    rsi,rax
    12a6:	48 8d 05 be 0d 00 00 	lea    rax,[rip+0xdbe]        # 206b <_IO_stdin_used+0x6b>
    12ad:	48 89 c7             	mov    rdi,rax
    12b0:	b8 00 00 00 00       	mov    eax,0x0
    12b5:	e8 c6 fd ff ff       	call   1080 <printf@plt>
    12ba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    12be:	48 89 c7             	mov    rdi,rax
    12c1:	e8 6a fd ff ff       	call   1030 <free@plt>
    12c6:	b8 00 00 00 00       	mov    eax,0x0
    12cb:	c9                   	leave  
    12cc:	c3                   	ret    

00000000000012cd <sort_cmp>:
    12cd:	f3 0f 1e fa          	endbr64 
    12d1:	55                   	push   rbp
    12d2:	48 89 e5             	mov    rbp,rsp
    12d5:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    12d9:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    12dd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    12e1:	48 8b 00             	mov    rax,QWORD PTR [rax]
    12e4:	89 c2                	mov    edx,eax
    12e6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    12ea:	48 8b 00             	mov    rax,QWORD PTR [rax]
    12ed:	89 c1                	mov    ecx,eax
    12ef:	89 d0                	mov    eax,edx
    12f1:	29 c8                	sub    eax,ecx
    12f3:	5d                   	pop    rbp
    12f4:	c3                   	ret    

00000000000012f5 <crack_password>:
    12f5:	f3 0f 1e fa          	endbr64 
    12f9:	55                   	push   rbp
    12fa:	48 89 e5             	mov    rbp,rsp
    12fd:	41 57                	push   r15
    12ff:	41 56                	push   r14
    1301:	41 55                	push   r13
    1303:	41 54                	push   r12
    1305:	53                   	push   rbx
    1306:	48 81 ec 38 01 00 00 	sub    rsp,0x138
    130d:	89 bd 0c ff ff ff    	mov    DWORD PTR [rbp-0xf4],edi
    1313:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    131a:	00 00 
    131c:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
    1320:	31 c0                	xor    eax,eax
    1322:	48 89 e0             	mov    rax,rsp
    1325:	48 89 c3             	mov    rbx,rax
    1328:	c7 85 4c ff ff ff 40 	mov    DWORD PTR [rbp-0xb4],0x40
    132f:	00 00 00 
    1332:	c6 85 20 ff ff ff 20 	mov    BYTE PTR [rbp-0xe0],0x20
    1339:	c6 85 21 ff ff ff 7f 	mov    BYTE PTR [rbp-0xdf],0x7f
    1340:	0f be 85 21 ff ff ff 	movsx  eax,BYTE PTR [rbp-0xdf]
    1347:	0f be 95 20 ff ff ff 	movsx  edx,BYTE PTR [rbp-0xe0]
    134e:	29 d0                	sub    eax,edx
    1350:	89 85 50 ff ff ff    	mov    DWORD PTR [rbp-0xb0],eax
    1356:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [rbp-0xb4]
    135c:	48 98                	cdqe   
    135e:	48 89 c7             	mov    rdi,rax
    1361:	e8 5a fd ff ff       	call   10c0 <malloc@plt>
    1366:	48 89 85 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rax
    136d:	48 83 bd 68 ff ff ff 	cmp    QWORD PTR [rbp-0x98],0x0
    1374:	00 
    1375:	75 0a                	jne    1381 <crack_password+0x8c>
    1377:	bf 01 00 00 00       	mov    edi,0x1
    137c:	e8 5f fd ff ff       	call   10e0 <exit@plt>
    1381:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [rbp-0xb4]
    1387:	48 98                	cdqe   
    1389:	48 8b 8d 68 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x98]
    1390:	48 89 c2             	mov    rdx,rax
    1393:	be 00 00 00 00       	mov    esi,0x0
    1398:	48 89 cf             	mov    rdi,rcx
    139b:	e8 f0 fc ff ff       	call   1090 <memset@plt>
    13a0:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [rbp-0xb4]
    13a6:	83 c0 40             	add    eax,0x40
    13a9:	48 98                	cdqe   
    13ab:	48 83 e8 01          	sub    rax,0x1
    13af:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
    13b6:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [rbp-0xb4]
    13bc:	83 c0 40             	add    eax,0x40
    13bf:	48 98                	cdqe   
    13c1:	49 89 c4             	mov    r12,rax
    13c4:	41 bd 00 00 00 00    	mov    r13d,0x0
    13ca:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [rbp-0xb4]
    13d0:	83 c0 40             	add    eax,0x40
    13d3:	48 98                	cdqe   
    13d5:	49 89 c6             	mov    r14,rax
    13d8:	41 bf 00 00 00 00    	mov    r15d,0x0
    13de:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [rbp-0xb4]
    13e4:	83 c0 40             	add    eax,0x40
    13e7:	48 63 d0             	movsxd rdx,eax
    13ea:	b8 10 00 00 00       	mov    eax,0x10
    13ef:	48 83 e8 01          	sub    rax,0x1
    13f3:	48 01 d0             	add    rax,rdx
    13f6:	be 10 00 00 00       	mov    esi,0x10
    13fb:	ba 00 00 00 00       	mov    edx,0x0
    1400:	48 f7 f6             	div    rsi
    1403:	48 6b d0 10          	imul   rdx,rax,0x10
    1407:	48 89 d0             	mov    rax,rdx
    140a:	48 25 00 f0 ff ff    	and    rax,0xfffffffffffff000
    1410:	48 89 e1             	mov    rcx,rsp
    1413:	48 29 c1             	sub    rcx,rax
    1416:	48 39 cc             	cmp    rsp,rcx
    1419:	74 12                	je     142d <crack_password+0x138>
    141b:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    1422:	48 83 8c 24 f8 0f 00 	or     QWORD PTR [rsp+0xff8],0x0
    1429:	00 00 
    142b:	eb e9                	jmp    1416 <crack_password+0x121>
    142d:	48 89 d0             	mov    rax,rdx
    1430:	25 ff 0f 00 00       	and    eax,0xfff
    1435:	48 29 c4             	sub    rsp,rax
    1438:	48 89 d0             	mov    rax,rdx
    143b:	25 ff 0f 00 00       	and    eax,0xfff
    1440:	48 85 c0             	test   rax,rax
    1443:	74 13                	je     1458 <crack_password+0x163>
    1445:	48 89 d0             	mov    rax,rdx
    1448:	25 ff 0f 00 00       	and    eax,0xfff
    144d:	48 83 e8 08          	sub    rax,0x8
    1451:	48 01 e0             	add    rax,rsp
    1454:	48 83 08 00          	or     QWORD PTR [rax],0x0
    1458:	48 89 e0             	mov    rax,rsp
    145b:	48 83 c0 00          	add    rax,0x0
    145f:	48 89 85 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rax
    1466:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    146c:	48 98                	cdqe   
    146e:	48 83 e8 01          	sub    rax,0x1
    1472:	48 89 45 80          	mov    QWORD PTR [rbp-0x80],rax
    1476:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    147c:	48 98                	cdqe   
    147e:	48 89 85 f0 fe ff ff 	mov    QWORD PTR [rbp-0x110],rax
    1485:	48 c7 85 f8 fe ff ff 	mov    QWORD PTR [rbp-0x108],0x0
    148c:	00 00 00 00 
    1490:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    1496:	48 98                	cdqe   
    1498:	48 89 85 e0 fe ff ff 	mov    QWORD PTR [rbp-0x120],rax
    149f:	48 c7 85 e8 fe ff ff 	mov    QWORD PTR [rbp-0x118],0x0
    14a6:	00 00 00 00 
    14aa:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    14b0:	48 98                	cdqe   
    14b2:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    14b9:	00 
    14ba:	b8 10 00 00 00       	mov    eax,0x10
    14bf:	48 83 e8 01          	sub    rax,0x1
    14c3:	48 01 d0             	add    rax,rdx
    14c6:	be 10 00 00 00       	mov    esi,0x10
    14cb:	ba 00 00 00 00       	mov    edx,0x0
    14d0:	48 f7 f6             	div    rsi
    14d3:	48 6b c0 10          	imul   rax,rax,0x10
    14d7:	48 89 c1             	mov    rcx,rax
    14da:	48 81 e1 00 f0 ff ff 	and    rcx,0xfffffffffffff000
    14e1:	48 89 e2             	mov    rdx,rsp
    14e4:	48 29 ca             	sub    rdx,rcx
    14e7:	48 39 d4             	cmp    rsp,rdx
    14ea:	74 12                	je     14fe <crack_password+0x209>
    14ec:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    14f3:	48 83 8c 24 f8 0f 00 	or     QWORD PTR [rsp+0xff8],0x0
    14fa:	00 00 
    14fc:	eb e9                	jmp    14e7 <crack_password+0x1f2>
    14fe:	48 89 c2             	mov    rdx,rax
    1501:	81 e2 ff 0f 00 00    	and    edx,0xfff
    1507:	48 29 d4             	sub    rsp,rdx
    150a:	48 89 c2             	mov    rdx,rax
    150d:	81 e2 ff 0f 00 00    	and    edx,0xfff
    1513:	48 85 d2             	test   rdx,rdx
    1516:	74 10                	je     1528 <crack_password+0x233>
    1518:	25 ff 0f 00 00       	and    eax,0xfff
    151d:	48 83 e8 08          	sub    rax,0x8
    1521:	48 01 e0             	add    rax,rsp
    1524:	48 83 08 00          	or     QWORD PTR [rax],0x0
    1528:	48 89 e0             	mov    rax,rsp
    152b:	48 83 c0 07          	add    rax,0x7
    152f:	48 c1 e8 03          	shr    rax,0x3
    1533:	48 c1 e0 03          	shl    rax,0x3
    1537:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
    153b:	c7 85 24 ff ff ff 00 	mov    DWORD PTR [rbp-0xdc],0x0
    1542:	00 00 00 
    1545:	e9 98 00 00 00       	jmp    15e2 <crack_password+0x2ed>
    154a:	8b 85 0c ff ff ff    	mov    eax,DWORD PTR [rbp-0xf4]
    1550:	48 98                	cdqe   
    1552:	48 c1 e0 02          	shl    rax,0x2
    1556:	48 89 c7             	mov    rdi,rax
    1559:	e8 62 fb ff ff       	call   10c0 <malloc@plt>
    155e:	48 89 c1             	mov    rcx,rax
    1561:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    1565:	8b 95 24 ff ff ff    	mov    edx,DWORD PTR [rbp-0xdc]
    156b:	48 63 d2             	movsxd rdx,edx
    156e:	48 89 0c d0          	mov    QWORD PTR [rax+rdx*8],rcx
    1572:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    1576:	8b 95 24 ff ff ff    	mov    edx,DWORD PTR [rbp-0xdc]
    157c:	48 63 d2             	movsxd rdx,edx
    157f:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
    1583:	48 85 c0             	test   rax,rax
    1586:	75 53                	jne    15db <crack_password+0x2e6>
    1588:	c7 85 28 ff ff ff 00 	mov    DWORD PTR [rbp-0xd8],0x0
    158f:	00 00 00 
    1592:	eb 20                	jmp    15b4 <crack_password+0x2bf>
    1594:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    1598:	8b 95 28 ff ff ff    	mov    edx,DWORD PTR [rbp-0xd8]
    159e:	48 63 d2             	movsxd rdx,edx
    15a1:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
    15a5:	48 89 c7             	mov    rdi,rax
    15a8:	e8 83 fa ff ff       	call   1030 <free@plt>
    15ad:	83 85 28 ff ff ff 01 	add    DWORD PTR [rbp-0xd8],0x1
    15b4:	8b 85 28 ff ff ff    	mov    eax,DWORD PTR [rbp-0xd8]
    15ba:	3b 85 24 ff ff ff    	cmp    eax,DWORD PTR [rbp-0xdc]
    15c0:	7c d2                	jl     1594 <crack_password+0x29f>
    15c2:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    15c9:	48 89 c7             	mov    rdi,rax
    15cc:	e8 5f fa ff ff       	call   1030 <free@plt>
    15d1:	bf 01 00 00 00       	mov    edi,0x1
    15d6:	e8 05 fb ff ff       	call   10e0 <exit@plt>
    15db:	83 85 24 ff ff ff 01 	add    DWORD PTR [rbp-0xdc],0x1
    15e2:	8b 85 24 ff ff ff    	mov    eax,DWORD PTR [rbp-0xdc]
    15e8:	3b 85 50 ff ff ff    	cmp    eax,DWORD PTR [rbp-0xb0]
    15ee:	0f 8c 56 ff ff ff    	jl     154a <crack_password+0x255>
    15f4:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    15fa:	48 98                	cdqe   
    15fc:	48 83 e8 01          	sub    rax,0x1
    1600:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
    1604:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    160a:	48 98                	cdqe   
    160c:	48 89 85 d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],rax
    1613:	48 c7 85 d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],0x0
    161a:	00 00 00 00 
    161e:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    1624:	48 98                	cdqe   
    1626:	48 89 85 c0 fe ff ff 	mov    QWORD PTR [rbp-0x140],rax
    162d:	48 c7 85 c8 fe ff ff 	mov    QWORD PTR [rbp-0x138],0x0
    1634:	00 00 00 00 
    1638:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    163e:	48 98                	cdqe   
    1640:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
    1647:	00 
    1648:	b8 10 00 00 00       	mov    eax,0x10
    164d:	48 83 e8 01          	sub    rax,0x1
    1651:	48 01 d0             	add    rax,rdx
    1654:	be 10 00 00 00       	mov    esi,0x10
    1659:	ba 00 00 00 00       	mov    edx,0x0
    165e:	48 f7 f6             	div    rsi
    1661:	48 6b c0 10          	imul   rax,rax,0x10
    1665:	48 89 c1             	mov    rcx,rax
    1668:	48 81 e1 00 f0 ff ff 	and    rcx,0xfffffffffffff000
    166f:	48 89 e2             	mov    rdx,rsp
    1672:	48 29 ca             	sub    rdx,rcx
    1675:	48 39 d4             	cmp    rsp,rdx
    1678:	74 12                	je     168c <crack_password+0x397>
    167a:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    1681:	48 83 8c 24 f8 0f 00 	or     QWORD PTR [rsp+0xff8],0x0
    1688:	00 00 
    168a:	eb e9                	jmp    1675 <crack_password+0x380>
    168c:	48 89 c2             	mov    rdx,rax
    168f:	81 e2 ff 0f 00 00    	and    edx,0xfff
    1695:	48 29 d4             	sub    rsp,rdx
    1698:	48 89 c2             	mov    rdx,rax
    169b:	81 e2 ff 0f 00 00    	and    edx,0xfff
    16a1:	48 85 d2             	test   rdx,rdx
    16a4:	74 10                	je     16b6 <crack_password+0x3c1>
    16a6:	25 ff 0f 00 00       	and    eax,0xfff
    16ab:	48 83 e8 08          	sub    rax,0x8
    16af:	48 01 e0             	add    rax,rsp
    16b2:	48 83 08 00          	or     QWORD PTR [rax],0x0
    16b6:	48 89 e0             	mov    rax,rsp
    16b9:	48 83 c0 03          	add    rax,0x3
    16bd:	48 c1 e8 02          	shr    rax,0x2
    16c1:	48 c1 e0 02          	shl    rax,0x2
    16c5:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
    16c9:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    16cf:	48 98                	cdqe   
    16d1:	48 83 e8 01          	sub    rax,0x1
    16d5:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
    16d9:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    16df:	48 98                	cdqe   
    16e1:	48 89 85 b0 fe ff ff 	mov    QWORD PTR [rbp-0x150],rax
    16e8:	48 c7 85 b8 fe ff ff 	mov    QWORD PTR [rbp-0x148],0x0
    16ef:	00 00 00 00 
    16f3:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    16f9:	48 98                	cdqe   
    16fb:	48 89 85 a0 fe ff ff 	mov    QWORD PTR [rbp-0x160],rax
    1702:	48 c7 85 a8 fe ff ff 	mov    QWORD PTR [rbp-0x158],0x0
    1709:	00 00 00 00 
    170d:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb0]
    1713:	48 98                	cdqe   
    1715:	ba 10 00 00 00       	mov    edx,0x10
    171a:	48 83 ea 01          	sub    rdx,0x1
    171e:	48 01 d0             	add    rax,rdx
    1721:	be 10 00 00 00       	mov    esi,0x10
    1726:	ba 00 00 00 00       	mov    edx,0x0
    172b:	48 f7 f6             	div    rsi
    172e:	48 6b c0 10          	imul   rax,rax,0x10
    1732:	48 89 c1             	mov    rcx,rax
    1735:	48 81 e1 00 f0 ff ff 	and    rcx,0xfffffffffffff000
    173c:	48 89 e2             	mov    rdx,rsp
    173f:	48 29 ca             	sub    rdx,rcx
    1742:	48 39 d4             	cmp    rsp,rdx
    1745:	74 12                	je     1759 <crack_password+0x464>
    1747:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    174e:	48 83 8c 24 f8 0f 00 	or     QWORD PTR [rsp+0xff8],0x0
    1755:	00 00 
    1757:	eb e9                	jmp    1742 <crack_password+0x44d>
    1759:	48 89 c2             	mov    rdx,rax
    175c:	81 e2 ff 0f 00 00    	and    edx,0xfff
    1762:	48 29 d4             	sub    rsp,rdx
    1765:	48 89 c2             	mov    rdx,rax
    1768:	81 e2 ff 0f 00 00    	and    edx,0xfff
    176e:	48 85 d2             	test   rdx,rdx
    1771:	74 10                	je     1783 <crack_password+0x48e>
    1773:	25 ff 0f 00 00       	and    eax,0xfff
    1778:	48 83 e8 08          	sub    rax,0x8
    177c:	48 01 e0             	add    rax,rsp
    177f:	48 83 08 00          	or     QWORD PTR [rax],0x0
    1783:	48 89 e0             	mov    rax,rsp
    1786:	48 83 c0 00          	add    rax,0x0
    178a:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
    178e:	0f b6 85 20 ff ff ff 	movzx  eax,BYTE PTR [rbp-0xe0]
    1795:	88 85 1d ff ff ff    	mov    BYTE PTR [rbp-0xe3],al
    179b:	eb 30                	jmp    17cd <crack_password+0x4d8>
    179d:	0f be 85 1d ff ff ff 	movsx  eax,BYTE PTR [rbp-0xe3]
    17a4:	0f be 95 20 ff ff ff 	movsx  edx,BYTE PTR [rbp-0xe0]
    17ab:	29 d0                	sub    eax,edx
    17ad:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
    17b1:	48 98                	cdqe   
    17b3:	0f b6 8d 1d ff ff ff 	movzx  ecx,BYTE PTR [rbp-0xe3]
    17ba:	88 0c 02             	mov    BYTE PTR [rdx+rax*1],cl
    17bd:	0f b6 85 1d ff ff ff 	movzx  eax,BYTE PTR [rbp-0xe3]
    17c4:	83 c0 01             	add    eax,0x1
    17c7:	88 85 1d ff ff ff    	mov    BYTE PTR [rbp-0xe3],al
    17cd:	0f b6 85 1d ff ff ff 	movzx  eax,BYTE PTR [rbp-0xe3]
    17d4:	3a 85 21 ff ff ff    	cmp    al,BYTE PTR [rbp-0xdf]
    17da:	7c c1                	jl     179d <crack_password+0x4a8>
    17dc:	8b 85 0c ff ff ff    	mov    eax,DWORD PTR [rbp-0xf4]
    17e2:	89 c6                	mov    esi,eax
    17e4:	48 8d 05 95 08 00 00 	lea    rax,[rip+0x895]        # 2080 <_IO_stdin_used+0x80>
    17eb:	48 89 c7             	mov    rdi,rax
    17ee:	b8 00 00 00 00       	mov    eax,0x0
    17f3:	e8 88 f8 ff ff       	call   1080 <printf@plt>
    17f8:	c7 85 2c ff ff ff 00 	mov    DWORD PTR [rbp-0xd4],0x0
    17ff:	00 00 00 
    1802:	e9 a0 03 00 00       	jmp    1ba7 <crack_password+0x8b2>
    1807:	c7 85 30 ff ff ff 00 	mov    DWORD PTR [rbp-0xd0],0x0
    180e:	00 00 00 
    1811:	e9 0f 02 00 00       	jmp    1a25 <crack_password+0x730>
    1816:	c7 85 34 ff ff ff 00 	mov    DWORD PTR [rbp-0xcc],0x0
    181d:	00 00 00 
    1820:	eb 64                	jmp    1886 <crack_password+0x591>
    1822:	e8 c9 f8 ff ff       	call   10f0 <rand@plt>
    1827:	99                   	cdq    
    1828:	f7 bd 50 ff ff ff    	idiv   DWORD PTR [rbp-0xb0]
    182e:	89 95 64 ff ff ff    	mov    DWORD PTR [rbp-0x9c],edx
    1834:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
    1838:	8b 85 34 ff ff ff    	mov    eax,DWORD PTR [rbp-0xcc]
    183e:	48 98                	cdqe   
    1840:	0f b6 04 02          	movzx  eax,BYTE PTR [rdx+rax*1]
    1844:	88 85 23 ff ff ff    	mov    BYTE PTR [rbp-0xdd],al
    184a:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
    184e:	8b 85 64 ff ff ff    	mov    eax,DWORD PTR [rbp-0x9c]
    1854:	48 98                	cdqe   
    1856:	0f b6 0c 02          	movzx  ecx,BYTE PTR [rdx+rax*1]
    185a:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
    185e:	8b 85 34 ff ff ff    	mov    eax,DWORD PTR [rbp-0xcc]
    1864:	48 98                	cdqe   
    1866:	88 0c 02             	mov    BYTE PTR [rdx+rax*1],cl
    1869:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
    186d:	8b 85 64 ff ff ff    	mov    eax,DWORD PTR [rbp-0x9c]
    1873:	48 98                	cdqe   
    1875:	0f b6 8d 23 ff ff ff 	movzx  ecx,BYTE PTR [rbp-0xdd]
    187c:	88 0c 02             	mov    BYTE PTR [rdx+rax*1],cl
    187f:	83 85 34 ff ff ff 01 	add    DWORD PTR [rbp-0xcc],0x1
    1886:	8b 85 34 ff ff ff    	mov    eax,DWORD PTR [rbp-0xcc]
    188c:	3b 85 50 ff ff ff    	cmp    eax,DWORD PTR [rbp-0xb0]
    1892:	7c 8e                	jl     1822 <crack_password+0x52d>
    1894:	e8 57 f8 ff ff       	call   10f0 <rand@plt>
    1899:	83 e0 3f             	and    eax,0x3f
    189c:	89 85 58 ff ff ff    	mov    DWORD PTR [rbp-0xa8],eax
    18a2:	8b 85 58 ff ff ff    	mov    eax,DWORD PTR [rbp-0xa8]
    18a8:	48 63 d0             	movsxd rdx,eax
    18ab:	48 8b 85 78 ff ff ff 	mov    rax,QWORD PTR [rbp-0x88]
    18b2:	48 01 d0             	add    rax,rdx
    18b5:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
    18b9:	48 8b 95 68 ff ff ff 	mov    rdx,QWORD PTR [rbp-0x98]
    18c0:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    18c4:	48 89 d6             	mov    rsi,rdx
    18c7:	48 89 c7             	mov    rdi,rax
    18ca:	e8 71 f7 ff ff       	call   1040 <strcpy@plt>
    18cf:	8b 85 2c ff ff ff    	mov    eax,DWORD PTR [rbp-0xd4]
    18d5:	48 98                	cdqe   
    18d7:	48 8d 50 01          	lea    rdx,[rax+0x1]
    18db:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    18df:	48 01 d0             	add    rax,rdx
    18e2:	c6 00 00             	mov    BYTE PTR [rax],0x0
    18e5:	c7 85 38 ff ff ff 00 	mov    DWORD PTR [rbp-0xc8],0x0
    18ec:	00 00 00 
    18ef:	e9 18 01 00 00       	jmp    1a0c <crack_password+0x717>
    18f4:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
    18f8:	8b 85 38 ff ff ff    	mov    eax,DWORD PTR [rbp-0xc8]
    18fe:	48 98                	cdqe   
    1900:	0f b6 04 02          	movzx  eax,BYTE PTR [rdx+rax*1]
    1904:	88 85 22 ff ff ff    	mov    BYTE PTR [rbp-0xde],al
    190a:	0f be 85 22 ff ff ff 	movsx  eax,BYTE PTR [rbp-0xde]
    1911:	0f be 95 20 ff ff ff 	movsx  edx,BYTE PTR [rbp-0xe0]
    1918:	29 d0                	sub    eax,edx
    191a:	89 85 5c ff ff ff    	mov    DWORD PTR [rbp-0xa4],eax
    1920:	8b 85 2c ff ff ff    	mov    eax,DWORD PTR [rbp-0xd4]
    1926:	48 63 d0             	movsxd rdx,eax
    1929:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    192d:	48 01 c2             	add    rdx,rax
    1930:	0f b6 85 22 ff ff ff 	movzx  eax,BYTE PTR [rbp-0xde]
    1937:	88 02                	mov    BYTE PTR [rdx],al
    1939:	b8 00 00 00 00       	mov    eax,0x0
    193e:	e8 ed 02 00 00       	call   1c30 <cpu_clock>
    1943:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
    1947:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
    194b:	48 89 c7             	mov    rdi,rax
    194e:	e8 e7 02 00 00       	call   1c3a <check_password>
    1953:	85 c0                	test   eax,eax
    1955:	74 62                	je     19b9 <crack_password+0x6c4>
    1957:	c7 85 3c ff ff ff 00 	mov    DWORD PTR [rbp-0xc4],0x0
    195e:	00 00 00 
    1961:	eb 20                	jmp    1983 <crack_password+0x68e>
    1963:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    1967:	8b 95 3c ff ff ff    	mov    edx,DWORD PTR [rbp-0xc4]
    196d:	48 63 d2             	movsxd rdx,edx
    1970:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
    1974:	48 89 c7             	mov    rdi,rax
    1977:	e8 b4 f6 ff ff       	call   1030 <free@plt>
    197c:	83 85 3c ff ff ff 01 	add    DWORD PTR [rbp-0xc4],0x1
    1983:	8b 85 3c ff ff ff    	mov    eax,DWORD PTR [rbp-0xc4]
    1989:	3b 85 50 ff ff ff    	cmp    eax,DWORD PTR [rbp-0xb0]
    198f:	7c d2                	jl     1963 <crack_password+0x66e>
    1991:	8b 85 2c ff ff ff    	mov    eax,DWORD PTR [rbp-0xd4]
    1997:	48 63 d0             	movsxd rdx,eax
    199a:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    19a1:	48 01 c2             	add    rdx,rax
    19a4:	0f b6 85 22 ff ff ff 	movzx  eax,BYTE PTR [rbp-0xde]
    19ab:	88 02                	mov    BYTE PTR [rdx],al
    19ad:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    19b4:	e9 51 02 00 00       	jmp    1c0a <crack_password+0x915>
    19b9:	b8 00 00 00 00       	mov    eax,0x0
    19be:	e8 6d 02 00 00       	call   1c30 <cpu_clock>
    19c3:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
    19c7:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    19cb:	89 c2                	mov    edx,eax
    19cd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    19d1:	89 c1                	mov    ecx,eax
    19d3:	89 d0                	mov    eax,edx
    19d5:	29 c8                	sub    eax,ecx
    19d7:	89 85 60 ff ff ff    	mov    DWORD PTR [rbp-0xa0],eax
    19dd:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    19e1:	8b 95 5c ff ff ff    	mov    edx,DWORD PTR [rbp-0xa4]
    19e7:	48 63 d2             	movsxd rdx,edx
    19ea:	48 8b 14 d0          	mov    rdx,QWORD PTR [rax+rdx*8]
    19ee:	8b 85 30 ff ff ff    	mov    eax,DWORD PTR [rbp-0xd0]
    19f4:	48 98                	cdqe   
    19f6:	48 c1 e0 02          	shl    rax,0x2
    19fa:	48 01 c2             	add    rdx,rax
    19fd:	8b 85 60 ff ff ff    	mov    eax,DWORD PTR [rbp-0xa0]
    1a03:	89 02                	mov    DWORD PTR [rdx],eax
    1a05:	83 85 38 ff ff ff 01 	add    DWORD PTR [rbp-0xc8],0x1
    1a0c:	8b 85 38 ff ff ff    	mov    eax,DWORD PTR [rbp-0xc8]
    1a12:	3b 85 50 ff ff ff    	cmp    eax,DWORD PTR [rbp-0xb0]
    1a18:	0f 8c d6 fe ff ff    	jl     18f4 <crack_password+0x5ff>
    1a1e:	83 85 30 ff ff ff 01 	add    DWORD PTR [rbp-0xd0],0x1
    1a25:	8b 85 30 ff ff ff    	mov    eax,DWORD PTR [rbp-0xd0]
    1a2b:	3b 85 0c ff ff ff    	cmp    eax,DWORD PTR [rbp-0xf4]
    1a31:	0f 8c df fd ff ff    	jl     1816 <crack_password+0x521>
    1a37:	c7 85 40 ff ff ff 00 	mov    DWORD PTR [rbp-0xc0],0x0
    1a3e:	00 00 00 
    1a41:	eb 6c                	jmp    1aaf <crack_password+0x7ba>
    1a43:	8b 85 0c ff ff ff    	mov    eax,DWORD PTR [rbp-0xf4]
    1a49:	48 63 f0             	movsxd rsi,eax
    1a4c:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    1a50:	8b 95 40 ff ff ff    	mov    edx,DWORD PTR [rbp-0xc0]
    1a56:	48 63 d2             	movsxd rdx,edx
    1a59:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
    1a5d:	48 8d 15 69 f8 ff ff 	lea    rdx,[rip+0xfffffffffffff869]        # 12cd <sort_cmp>
    1a64:	48 89 d1             	mov    rcx,rdx
    1a67:	ba 04 00 00 00       	mov    edx,0x4
    1a6c:	48 89 c7             	mov    rdi,rax
    1a6f:	e8 ec f5 ff ff       	call   1060 <qsort@plt>
    1a74:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    1a78:	8b 95 40 ff ff ff    	mov    edx,DWORD PTR [rbp-0xc0]
    1a7e:	48 63 d2             	movsxd rdx,edx
    1a81:	48 8b 14 d0          	mov    rdx,QWORD PTR [rax+rdx*8]
    1a85:	8b 85 0c ff ff ff    	mov    eax,DWORD PTR [rbp-0xf4]
    1a8b:	d1 f8                	sar    eax,1
    1a8d:	48 98                	cdqe   
    1a8f:	48 c1 e0 02          	shl    rax,0x2
    1a93:	48 01 d0             	add    rax,rdx
    1a96:	8b 08                	mov    ecx,DWORD PTR [rax]
    1a98:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
    1a9c:	8b 95 40 ff ff ff    	mov    edx,DWORD PTR [rbp-0xc0]
    1aa2:	48 63 d2             	movsxd rdx,edx
    1aa5:	89 0c 90             	mov    DWORD PTR [rax+rdx*4],ecx
    1aa8:	83 85 40 ff ff ff 01 	add    DWORD PTR [rbp-0xc0],0x1
    1aaf:	8b 85 40 ff ff ff    	mov    eax,DWORD PTR [rbp-0xc0]
    1ab5:	3b 85 50 ff ff ff    	cmp    eax,DWORD PTR [rbp-0xb0]
    1abb:	7c 86                	jl     1a43 <crack_password+0x74e>
    1abd:	c7 85 44 ff ff ff 00 	mov    DWORD PTR [rbp-0xbc],0x0
    1ac4:	00 00 00 
    1ac7:	0f b6 85 20 ff ff ff 	movzx  eax,BYTE PTR [rbp-0xe0]
    1ace:	88 85 1f ff ff ff    	mov    BYTE PTR [rbp-0xe1],al
    1ad4:	eb 7d                	jmp    1b53 <crack_password+0x85e>
    1ad6:	0f be 85 1f ff ff ff 	movsx  eax,BYTE PTR [rbp-0xe1]
    1add:	0f be 95 20 ff ff ff 	movsx  edx,BYTE PTR [rbp-0xe0]
    1ae4:	29 d0                	sub    eax,edx
    1ae6:	89 85 54 ff ff ff    	mov    DWORD PTR [rbp-0xac],eax
    1aec:	8b 85 2c ff ff ff    	mov    eax,DWORD PTR [rbp-0xd4]
    1af2:	48 63 d0             	movsxd rdx,eax
    1af5:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    1afc:	48 01 c2             	add    rdx,rax
    1aff:	0f b6 85 1f ff ff ff 	movzx  eax,BYTE PTR [rbp-0xe1]
    1b06:	88 02                	mov    BYTE PTR [rdx],al
    1b08:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
    1b0c:	8b 95 54 ff ff ff    	mov    edx,DWORD PTR [rbp-0xac]
    1b12:	48 63 d2             	movsxd rdx,edx
    1b15:	8b 04 90             	mov    eax,DWORD PTR [rax+rdx*4]
    1b18:	39 85 44 ff ff ff    	cmp    DWORD PTR [rbp-0xbc],eax
    1b1e:	7d 23                	jge    1b43 <crack_password+0x84e>
    1b20:	0f b6 85 1f ff ff ff 	movzx  eax,BYTE PTR [rbp-0xe1]
    1b27:	88 85 1e ff ff ff    	mov    BYTE PTR [rbp-0xe2],al
    1b2d:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
    1b31:	8b 95 54 ff ff ff    	mov    edx,DWORD PTR [rbp-0xac]
    1b37:	48 63 d2             	movsxd rdx,edx
    1b3a:	8b 04 90             	mov    eax,DWORD PTR [rax+rdx*4]
    1b3d:	89 85 44 ff ff ff    	mov    DWORD PTR [rbp-0xbc],eax
    1b43:	0f b6 85 1f ff ff ff 	movzx  eax,BYTE PTR [rbp-0xe1]
    1b4a:	83 c0 01             	add    eax,0x1
    1b4d:	88 85 1f ff ff ff    	mov    BYTE PTR [rbp-0xe1],al
    1b53:	0f b6 85 1f ff ff ff 	movzx  eax,BYTE PTR [rbp-0xe1]
    1b5a:	3a 85 21 ff ff ff    	cmp    al,BYTE PTR [rbp-0xdf]
    1b60:	0f 8c 70 ff ff ff    	jl     1ad6 <crack_password+0x7e1>
    1b66:	8b 85 2c ff ff ff    	mov    eax,DWORD PTR [rbp-0xd4]
    1b6c:	48 63 d0             	movsxd rdx,eax
    1b6f:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    1b76:	48 01 c2             	add    rdx,rax
    1b79:	0f b6 85 1e ff ff ff 	movzx  eax,BYTE PTR [rbp-0xe2]
    1b80:	88 02                	mov    BYTE PTR [rdx],al
    1b82:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    1b89:	48 89 c6             	mov    rsi,rax
    1b8c:	48 8d 05 1d 05 00 00 	lea    rax,[rip+0x51d]        # 20b0 <_IO_stdin_used+0xb0>
    1b93:	48 89 c7             	mov    rdi,rax
    1b96:	b8 00 00 00 00       	mov    eax,0x0
    1b9b:	e8 e0 f4 ff ff       	call   1080 <printf@plt>
    1ba0:	83 85 2c ff ff ff 01 	add    DWORD PTR [rbp-0xd4],0x1
    1ba7:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [rbp-0xb4]
    1bad:	83 e8 01             	sub    eax,0x1
    1bb0:	39 85 2c ff ff ff    	cmp    DWORD PTR [rbp-0xd4],eax
    1bb6:	0f 8c 4b fc ff ff    	jl     1807 <crack_password+0x512>
    1bbc:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    1bc3:	48 89 c7             	mov    rdi,rax
    1bc6:	e8 65 f4 ff ff       	call   1030 <free@plt>
    1bcb:	c7 85 48 ff ff ff 00 	mov    DWORD PTR [rbp-0xb8],0x0
    1bd2:	00 00 00 
    1bd5:	eb 20                	jmp    1bf7 <crack_password+0x902>
    1bd7:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
    1bdb:	8b 95 48 ff ff ff    	mov    edx,DWORD PTR [rbp-0xb8]
    1be1:	48 63 d2             	movsxd rdx,edx
    1be4:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
    1be8:	48 89 c7             	mov    rdi,rax
    1beb:	e8 40 f4 ff ff       	call   1030 <free@plt>
    1bf0:	83 85 48 ff ff ff 01 	add    DWORD PTR [rbp-0xb8],0x1
    1bf7:	8b 85 48 ff ff ff    	mov    eax,DWORD PTR [rbp-0xb8]
    1bfd:	3b 85 50 ff ff ff    	cmp    eax,DWORD PTR [rbp-0xb0]
    1c03:	7c d2                	jl     1bd7 <crack_password+0x8e2>
    1c05:	b8 00 00 00 00       	mov    eax,0x0
    1c0a:	48 89 dc             	mov    rsp,rbx
    1c0d:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    1c11:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    1c18:	00 00 
    1c1a:	74 05                	je     1c21 <crack_password+0x92c>
    1c1c:	e8 4f f4 ff ff       	call   1070 <__stack_chk_fail@plt>
    1c21:	48 8d 65 d8          	lea    rsp,[rbp-0x28]
    1c25:	5b                   	pop    rbx
    1c26:	41 5c                	pop    r12
    1c28:	41 5d                	pop    r13
    1c2a:	41 5e                	pop    r14
    1c2c:	41 5f                	pop    r15
    1c2e:	5d                   	pop    rbp
    1c2f:	c3                   	ret    

0000000000001c30 <cpu_clock>:
    1c30:	0f 31                	rdtsc  
    1c32:	48 c1 e2 20          	shl    rdx,0x20
    1c36:	48 09 d0             	or     rax,rdx
    1c39:	c3                   	ret    

0000000000001c3a <check_password>:
    1c3a:	f3 0f 1e fa          	endbr64 
    1c3e:	55                   	push   rbp
    1c3f:	48 89 e5             	mov    rbp,rsp
    1c42:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    1c46:	48 8d 05 8b 04 00 00 	lea    rax,[rip+0x48b]        # 20d8 <_IO_stdin_used+0xd8>
    1c4d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1c51:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1c55:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    1c58:	84 c0                	test   al,al
    1c5a:	74 0b                	je     1c67 <check_password+0x2d>
    1c5c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1c60:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    1c63:	84 c0                	test   al,al
    1c65:	75 18                	jne    1c7f <check_password+0x45>
    1c67:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1c6b:	0f b6 10             	movzx  edx,BYTE PTR [rax]
    1c6e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1c72:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    1c75:	38 c2                	cmp    dl,al
    1c77:	0f 94 c0             	sete   al
    1c7a:	0f b6 c0             	movzx  eax,al
    1c7d:	eb 25                	jmp    1ca4 <check_password+0x6a>
    1c7f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1c83:	0f b6 10             	movzx  edx,BYTE PTR [rax]
    1c86:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1c8a:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    1c8d:	38 c2                	cmp    dl,al
    1c8f:	74 07                	je     1c98 <check_password+0x5e>
    1c91:	b8 00 00 00 00       	mov    eax,0x0
    1c96:	eb 0c                	jmp    1ca4 <check_password+0x6a>
    1c98:	48 83 45 e8 01       	add    QWORD PTR [rbp-0x18],0x1
    1c9d:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
    1ca2:	eb ad                	jmp    1c51 <check_password+0x17>
    1ca4:	5d                   	pop    rbp
    1ca5:	c3                   	ret    

Disassembly of section .fini:

0000000000001ca8 <_fini>:
    1ca8:	f3 0f 1e fa          	endbr64 
    1cac:	48 83 ec 08          	sub    rsp,0x8
    1cb0:	48 83 c4 08          	add    rsp,0x8
    1cb4:	c3                   	ret    
