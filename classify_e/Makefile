client_LDADD = -L ../include -L ../libreg\
	-L../librule \
	-L../libua \
	-L ./ \
	-lrule \
	-lua \
	-lreg \
	-lsvm \
	-lpthread \
	-lm \
	-lstdc++

object=classify_e.o ds_lib_seu.o

classify_e:classify_e.o ds_lib_seu.o
	gcc -o classify_e $(object) $(client_LDADD)
classify_e.o:classify_e.c
	gcc -c classify_e.c $(client_LDADD)
ds_lib_seu.o:ds_lib_seu.c
	gcc -c ds_lib_seu.c
clean:
	rm -f classify_e $(object)