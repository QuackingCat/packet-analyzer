global_flags = -Wall -pedantic
path_protos := protos
path_objs := objs
srcs := $(wildcard $(path_protos)/*.c)
objs := $(patsubst $(path_protos)/%.c,$(path_objs)/%.o,$(srcs))

allsrcs := $(wildcard $(path_protos)/*.c) $(wildcard $(path_protos)/*.h) $(wildcard *.c) $(wildcard *.h)

all: protos.so analyzer


syn:
	gcc $(allsrcs) -fsyntax-only


analyzer: analyzer.c packet.h
	gcc analyzer.c $(global_flags) -o analyzer



protos.so: pre $(objs)
	gcc $(objs) -shared $(global_flags) -o protos.so

pre:
	mkdir -p $(path_objs)

	

$(path_objs)/%.o: $(path_protos)/%.c $(path_protos)/%.h $(path_protos)/proto.h packet.h
	gcc $(patsubst $(path_objs)/%.o,$(path_protos)/%.c,$@) -shared -c $(global_flags) -o $@


# fallback dummy rule for header files that doesn't exists
%.h: ;