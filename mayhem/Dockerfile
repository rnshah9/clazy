FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y g++ cmake clang llvm-dev git-core libclang-dev build-essential

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_unquoteString.cpp -fsanitize=fuzzer,address -L /install/lib/ -l:ClazyPlugin.so -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y llvm-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_unquoteString
ENV LD_LIBRARY_PATH=/install/lib
