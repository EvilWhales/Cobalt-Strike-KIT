import sys
is_cpp=False # cpp needs to add `extern "C"` at the start of the function declaration
allh="waddup.tsv"

e=dict()

with open(allh) as fh:
    for l in fh.readlines():
        l = l.strip()
        if (not l):
            continue

# surely this owuld never break
        (fn, fn32, fndecl)= l.split("\t")

        e[fn] = [fn, fn32, fndecl]


wein = set()

# for each files provided by the user
for f in sys.argv:
    with open(f) as fh:
        content = fh.read()
        for k in e.keys():
            if k in content:
                wein.add(k)

for v in list(wein):
    (fn, fn32, fndecl)= e[v]

    # if the fn is in the file
    # print the function declaration and define the function
    print(f"{fndecl}")
    print(f"#define {fn} {fn32}")


