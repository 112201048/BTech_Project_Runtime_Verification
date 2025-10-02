all: sample tool

sample: sample.c
	gcc -g -o sample sample.c

tool: tool.cpp
	g++ -o tool tool.cpp -I include/

clean:
	rm -f sample tool