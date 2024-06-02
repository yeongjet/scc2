CC=gcc
# OBJDIR=.cbj
# QJS_OBJS=$(OBJDIR)/dynarray.c $(OBJDIR)/dynstring.c $(OBJDIR)/error.c $(OBJDIR)/gencode.c \
# 	$(OBJDIR)/grammar.c $(OBJDIR)/lex.c $(OBJDIR)/operand.c $(OBJDIR)/outcoff.c $(OBJDIR)/scc.c \
# 	$(OBJDIR)/scc.c $(OBJDIR)/stack.c $(OBJDIR)/symbol.c 
OBJDIR=.cbj
QJS_OBJS=dynarray.c dynstring.c error.c gencode.c \
	grammar.c lex.c operand.c outcoff.c outpe.c \
	scc.c stack.c symbol.c 

scc: ${QJS_OBJS}
	$(CC) -g -o $@ $^