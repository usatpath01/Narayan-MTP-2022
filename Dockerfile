FROM ubuntu:20.04
RUN apt update
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
RUN apt install -y bison build-essential cmake flex git libedit-dev libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils
WORKDIR /myspace
RUN git clone https://github.com/iovisor/bcc.git
RUN mkdir bcc/build
WORKDIR /myspace/bcc/build
RUN pwd
RUN cmake ..
RUN make
RUN make install
RUN cmake -DPYTHON_CMD=python3 .. # build python3 binding
WORKDIR /myspace/bcc/build/src/python/
RUN make
RUN make install
WORKDIR /myspace/programs
COPY ./* ./
RUN apt update
RUN apt install -y linux-headers-$(uname -r)
