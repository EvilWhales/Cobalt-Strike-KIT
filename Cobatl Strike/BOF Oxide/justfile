
rust:
    RUSTFLAGS="-C target-cpu=x86-64 -C target-feature=+crt-static -C link-arg=-nostartfiles -C link-arg=-nodefaultlibs -C link-arg=-Wl,--gc-sections" \
    rustc --target x86_64-pc-windows-gnu \
    --cfg 'feature="data"' \
    --cfg 'feature="out"' \
    -C opt-level=z \
    -C panic=abort \
    -C debuginfo=0 \
    -C strip=symbols \
    -C codegen-units=1 \
    -C embed-bitcode=no \
    --emit=obj \
    src/lib.rs -o objects/rust_part.o

c:
    x86_64-w64-mingw32-gcc -c src/entry.c -o objects/c_part.o

view-bof:
    objdump -t bof.o

ld:
    x86_64-w64-mingw32-ld -r objects/rust_part.o objects/c_part.o -o objects/combined.o

copy: ld
    x86_64-w64-mingw32-objcopy \
        --remove-section=.drectve \
        --strip-symbol=@feat.00 \
        --remove-section=.bss \
        --strip-symbol=rust_begin_unwind \
        --strip-debug \
        objects/combined.o \
        bof.o

bof: rust c copy view-bof
