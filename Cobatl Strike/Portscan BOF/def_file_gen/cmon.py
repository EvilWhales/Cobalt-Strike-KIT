with open("./all.h") as fh:
    for l in fh.readlines():
        l=l.strip("\n").replace("\t", " ")

        # ignore comments and empty lines
        if (not len(l) or l[0] == "/"):
            continue

        # DECLSPEC_IMPORT WINBOOL WINAPI VERSION$VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);
        
        f = l.split("(")[0].strip().split(" ")[-1]
        c = f.split("$")[1]
        print(f"{c}\t{f}\t{l}")


