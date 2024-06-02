// ���Լ�����д��������������������Դ����

#include "scc.h"
Stack global_sym_stack,		// ȫ�ַ���ջ
	  local_sym_stack;		// �ֲ�����ջ
Type char_pointer_type,		// �ַ���ָ��				
	 int_type,				// int����
	 default_func_type;		// ȱʡ��������
/***********************************************************
 * ����:	���ҽṹ����
 * v:		���ű��
 **********************************************************/
Symbol *struct_search(int v)
{
    if (v >= tktable.count)
        return NULL;
	else
		return ((TkWord*)tktable.data[v])->sym_struct;
}

/***********************************************************
 * ����:	���ҽṹ���� 
 * v:		���ű��
 **********************************************************/
Symbol *sym_search(int v)
{
    if (v >= tktable.count)
        return NULL;
	else
		return ((TkWord*)tktable.data[v])->sym_identifier;
}

/***********************************************************
 * ����:	�����ŷ��ڷ���ջ�� 
 * v:		���ű��
 * type:	������������
 * c:		���Ź���ֵ 
 **********************************************************/
Symbol *sym_direct_push(Stack *ss, int v, Type *type, int c)
{
	Symbol s,*p;
    s.v = v;
	s.type.t = type->t;
	s.type.ref = type->ref;
    s.c = c;
    s.next = NULL;
	p = (Symbol*)stack_push(ss,&s,sizeof(Symbol));
    return p;
}

/*********************************************************** 
 * ����:	�����ŷ��ڷ���ջ��,��̬�ж��Ƿ���ȫ�ַ���ջ���Ǿֲ�����ջ
 * v:		���ű��
 * type:	������������
 * r:		���Ŵ洢����
 * c:		���Ź���ֵ
 **********************************************************/
Symbol *sym_push(int v, Type *type, int r, int c)
{
    Symbol *ps, **pps;
    TkWord *ts;
	Stack *ss;

    if (stack_is_empty(&local_sym_stack) == 0)
	{
		ss = &local_sym_stack;
	}
    else
	{
		ss = &global_sym_stack;
	}
    ps = sym_direct_push(ss,v,type,c);
	ps->r = r;    

    // ����¼�ṹ���Ա����������
	if((v & SC_STRUCT) || v < SC_ANOM)
	{
        // ���µ���sym_struct��sym_identifier�ֶ�
        ts = (TkWord*)tktable.data[(v & ~SC_STRUCT)];
        if (v & SC_STRUCT)
            pps = &ts->sym_struct;
        else
            pps = &ts->sym_identifier;
        ps->prev_tok = *pps;
        *pps = ps;
    }
    return ps;
}

/*********************************************************** 
 * ����:	����ջ�з���ֱ��ջ������Ϊ'b'
 * ptop:	����ջջ��
 * b:		����ָ��
 **********************************************************/
void sym_pop(Stack *ptop, Symbol *b)
{
    Symbol *s, **ps;
    TkWord *ts;
    int v;

    s = (Symbol*)stack_get_top(ptop);
    while(s != b) 
	{
        v = s->v;
        // ���µ��ʱ���sym_struct sym_identifier
		if((v & SC_STRUCT) || v < SC_ANOM)
		{
            ts = (TkWord*)tktable.data[(v & ~SC_STRUCT)];
            if (v & SC_STRUCT)
                ps = &ts->sym_struct;
            else
                ps = &ts->sym_identifier;
            *ps = s->prev_tok;
        }
		stack_pop(ptop);
        s = (Symbol*)stack_get_top(ptop);  	
    }
}

/*********************************************************** 
 * ����:	����ָ������
 * t:		ԭ��������
 **********************************************************/
void mk_pointer(Type *t)
{
	Symbol *s;
    s = sym_push(SC_ANOM, t, 0, -1);
    t->t = T_PTR ;
    t->ref = s;
}


/***********************************************************
 * ����:	�������ͳ���
 * t:		��������ָ��
 * a:		����ֵ
 **********************************************************/
int type_size(Type *t, int *a)
{
    Symbol *s;
    int bt;
	// ָ�����ͳ���Ϊ4���ֽ�
    int PTR_SIZE = 4;

    bt = t->t & T_BTYPE;
	switch(bt)
	{
    case T_STRUCT: 		
        s = t->ref;
        *a = s->r;
        return s->c;
		
	case T_PTR:
        if (t->t & T_ARRAY)
	{
            s = t->ref;
            return type_size(&s->type, a) * s->c;
        } 
		else 
		{
            *a = PTR_SIZE;
            return PTR_SIZE;
        }
		
	case T_INT:
        *a = 4;
        return 4;
		
	case T_SHORT:
        *a = 2;
        return 2;
		
	default:			// char, void, function       
        *a = 1;
        return 1;
    }
}

/*********************************************************** 
 * ����:	���������ŷ���ȫ�ַ��ű���
 * v:		���ű��
 * type:	������������
 **********************************************************/
Symbol *func_sym_push(int v, Type *type)
{
    Symbol *s, **ps;
    s = sym_direct_push(&global_sym_stack, v, type, 0);
	
	ps = &((TkWord*)tktable.data[v])->sym_identifier;
	// ͬ�����ţ��������ŷ������-> ->...s
	while (*ps != NULL)
		ps = &(*ps)->prev_tok;
	s->prev_tok = NULL;
	*ps = s;
    return s;
}

Symbol *var_sym_put(Type *type, int r, int v, int addr)
{
	Symbol *sym = NULL;
	if ((r & SC_VALMASK) == SC_LOCAL)			// �ֲ�����
	{  
		
        sym = sym_push(v, type, r, addr);
    } 
	else if (v && (r & SC_VALMASK) == SC_GLOBAL) // ȫ�ֱ���
	{
		sym = sym_search(v);
		if (sym)
			error("%s�ض���\n",((TkWord*)tktable.data[v])->spelling);
		else
		{
			sym = sym_push(v, type, r | SC_SYM, 0);
		}
	}
	//else �ַ�����������
	return sym;
}

/*********************************************************** 
 * ����:	�������Ʒ���ȫ�ַ��ű�
 * sec:		������
 * c:		���Ź���ֵ
 **********************************************************/
Symbol *sec_sym_put(char *sec,int c)
{
    TkWord* tp;
	Symbol *s;
	Type type;
	type.t = T_INT;
	tp = tkword_insert(sec);
	token = tp->tkcode;
	s = sym_push(token,&type,SC_GLOBAL,c); 
	return s;	
}