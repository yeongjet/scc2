// ���Լ�����д��������������������Դ����

#include "scc.h"
/* �����õ���ȫ�ֱ��� */
int rsym;						// ��¼returnָ��λ��
int ind = 0;					// ָ���ڴ����λ��
int loc;						// �ֲ�������ջ��λ��
int func_begin_ind;				// ������ʼָ��
int func_ret_sub;				// ���������ͷ�ջ�ռ��С
Symbol *sym_sec_rdata;			// ֻ���ڷ���
Operand opstack[OPSTACK_SIZE];  // ������ջ
Operand *optop;					// ������ջջ��

/***********************************************************
 * ����:	������д��һ���ֽ�
 * c:		�ֽ�ֵ
 **********************************************************/
void gen_byte(char c)
{
    int ind1;
    ind1 = ind + 1;
    if (ind1 > sec_text->data_allocated)
        section_realloc(sec_text, ind1);
    sec_text->data[ind] = c;
    ind = ind1;
}

/***********************************************************
instruction prefix
The Instruction prefixes are divided into four groups, each with a set of allowable prefix codes:
1.Lock and repeat prefixes
2.Segment override
3.Operand-size override
4.Address-size override
 **********************************************************/
/***********************************************************
 * ����:	����ָ��ǰ׺
 * opcode:	ָ��ǰ׺����
 **********************************************************/
void gen_prefix(char opcode)
{
	gen_byte(opcode);
}

/***********************************************************
 * ����:	���ɵ��ֽ�ָ��
 * opcode:  ָ�����
 **********************************************************/
void gen_opcode1(char opcode)
{
	gen_byte(opcode);
}

/***********************************************************
 * ����:	����˫�ֽ�ָ��
 * first:	ָ���һ���ֽ�
 * second:	ָ��ڶ����ֽ�
 **********************************************************/
void gen_opcode2(char first, char second)
{
	gen_byte(first);
	gen_byte(second);
}

/***********************************************************
 * ����:	����4�ֽڲ�����
 * c:		4�ֽڲ�����
 **********************************************************/
void gen_dword(unsigned int c)
{
    gen_byte(c);
    gen_byte(c >> 8);
    gen_byte(c >> 16);
    gen_byte(c >> 24);
}

/*********************************************************** 
 * ����:	���������tΪ���׵ĸ���������ת��ַ������Ե�ַ
 * t:		����
 * a:		ָ����תλ��
 **********************************************************/
void backpatch(int t, int a)
{
    int n, *ptr;
    while (t) 
	{
        ptr = (int *)(sec_text->data + t);
        n = *ptr; // ��һ����Ҫ����λ��
        *ptr = a - t - 4;
        t = n;
    }
}

/***********************************************************
 * ����:	��¼������ת��ַ��ָ����
 * s:		ǰһ��תָ���ַ
 **********************************************************/
int makelist(int s)
{
	int ind1;
    ind1 = ind + 4;
    if (ind1 > sec_text->data_allocated)
        section_realloc(sec_text, ind1);
    *(int *)(sec_text->data + ind) = s;
    s = ind;
    ind = ind1;
    return s;
}

/*********************************************************** 
 * ����:	����ȫ�ַ��ŵ�ַ,������COFF�ض�λ��¼
 * output constant with relocation if 'r & SC_SYM' is true 
 * r:		���Ŵ洢����
 * sym:		����ָ��
 * c:		���Ź���ֵ
 **********************************************************/
void gen_addr32(int r, Symbol *sym, int c)
{
    if (r & SC_SYM)
        coffreloc_add(sec_text, sym, ind, IMAGE_REL_I386_DIR32);
    gen_dword(c);
}

/*********************************************************** 
 * ����:		����ָ��Ѱַ��ʽ�ֽ�ModR/M,
 * mod:			ModR/M [7:6]
 * reg_opcode:	ModR/M [5:3]ָ�������3λ������ Դ������(�з���׼ȷ)
 * r_m:			ModR/M [2:0] Ŀ�������(�з���׼ȷ��
 * sym:		����ָ��
 * c:		���Ź���ֵ
 **********************************************************/
void gen_modrm(int mod,int reg_opcode, int r_m, Symbol *sym, int c)
{
	mod <<=  6;
    reg_opcode <<= 3;
	if(mod == 0xc0) // mod=11 �Ĵ���Ѱַ 89 E5(11 reg_opcode=100ESP r=101EBP) MOV EBP,ESP
	{
		gen_byte(mod | reg_opcode | (r_m & SC_VALMASK));
	}
    else if ((r_m & SC_VALMASK) == SC_GLOBAL) 
	{
		// mod=00 r=101 disp32  8b 05 50 30 40 00  MOV EAX,DWORD PTR DS:[403050]
		// 8B /r MOV r32,r/m32 Move r/m32 to r32
		// mod=00 r=101 disp32  89 05 14 30 40 00  MOV DWORD PTR DS:[403014],EAX
		// 89 /r MOV r/m32,r32 Move r32 to r/m32
        gen_byte(0x05 | reg_opcode); //ֱ��Ѱַ
        gen_addr32(r_m, sym, c);
    } 
	else if ((r_m & SC_VALMASK) == SC_LOCAL) 
	{
        if (c == (char)c)
		{
			// mod=01 r=101 disp8[EBP] 89 45 fc MOV DWORD PTR SS:[EBP-4],EAX
            gen_byte(0x45 | reg_opcode); 
            gen_byte(c);
        } 
		else 
		{
			// mod=10 r=101 disp32[EBP]
			gen_byte(0x85 | reg_opcode); 
			gen_dword(c);
        }
    } 
	else 
	{
		// mod=00 89 01(00 reg_opcode=000 EAX r=001ECX) MOV DWORD PTR DS:[ECX],EAX
        gen_byte(0x00 | reg_opcode | (r_m & SC_VALMASK)); 
    }
}


/*********************************************************** 
 * ����:	��������opd���ص��Ĵ���r��
 * r:		���Ŵ洢����
 * opd:		������ָ��
 **********************************************************/
void load(int r, Operand *opd)
{
    int v, ft, fc, fr;

    fr = opd->r;
    ft = opd->type.t;
    fc = opd->value;

    v = fr & SC_VALMASK;
    if (fr & SC_LVAL) 
	{
        if ((ft & T_BTYPE) == T_CHAR) 
		{
			// movsx -- move with sign-extention	
			// 0F BE /r	movsx r32,r/m8	move byte to doubleword,sign-extention
			gen_opcode2(0x0f,0xbe); 
        } 
		else if ((ft & T_BTYPE) == T_SHORT) 
		{
			// movsx -- move with sign-extention	
			// 0F BF /r	movsx r32,r/m16	move word to doubleword,sign-extention
            gen_opcode2(0x0f,0xbf); 
        } 
		else 
		{
			// 8B /r	mov r32,r/m32	mov r/m32 to r32
            gen_opcode1(0x8b);
        }
        gen_modrm(ADDR_OTHER,r, fr, opd->sym, fc);
    } 
	else 
	{
        if (v == SC_GLOBAL) 
		{
			// B8+ rd	mov r32,imm32		mov imm32 to r32
            gen_opcode1(0xb8 + r);	
            gen_addr32(fr, opd->sym, fc);
        } 
		else if (v == SC_LOCAL) 
		{			
			// LEA--Load Effective Address
			// 8D /r	LEA r32,m	Store effective address for m in register r32
            gen_opcode1(0x8d);
            gen_modrm(ADDR_OTHER,r, SC_LOCAL, opd->sym, fc);
        } 
		else if (v == SC_CMP) // ������c=a>b���
		{
		/*����������ɵ���������
		  00401384   39C8             CMP EAX,ECX
		  00401386   B8 00000000      MOV EAX,0
		  0040138B   0F9FC0           SETG AL
		  0040138E   8945 FC          MOV DWORD PTR SS:[EBP-4],EAX*/

			/*B8+ rd	mov r32,imm32		mov imm32 to r32*/
			gen_opcode1(0xb8 + r); /* mov r, 0*/
			gen_dword(0);
			
			// SETcc--Set Byte on Condition
			// OF 9F			SETG r/m8	Set byte if greater(ZF=0 and SF=OF)
			// 0F 8F cw/cd		JG rel16/32	jump near if greater(ZF=0 and SF=OF)
			gen_opcode2(0x0f,fc+16);
			gen_modrm(ADDR_REG,0,r,NULL,0);
        } 
		else if (v != r) 
		{
			// 89 /r	MOV r/m32,r32	Move r32 to r/m32
            gen_opcode1(0x89);
			gen_modrm(ADDR_REG,v,r,NULL,0);
        }
    }
}

/*********************************************************** 
 * ����:	���Ĵ���'r'�е�ֵ���������'opd'
 * r:		���Ŵ洢����
 * opd:		������ָ��
 **********************************************************/
void store(int r, Operand *opd)
{
    int fr, bt;
	
    fr = opd->r & SC_VALMASK;
    bt = opd->type.t & T_BTYPE;
    if (bt == T_SHORT)
		gen_prefix(0x66); //Operand-size override, 66H
	if (bt == T_CHAR)
		// 88 /r	MOV r/m,r8	Move r8 to r/m8
		gen_opcode1(0x88);
	else
		// 89 /r	MOV r/m32,r32	Move r32 to r/m32
        gen_opcode1(0x89);
	
    if (fr == SC_GLOBAL ||
        fr == SC_LOCAL ||
        (opd->r & SC_LVAL)) 
	{
        gen_modrm(ADDR_OTHER,r, opd->r, opd->sym, opd->value);
    }
}

/*********************************************************** 
 * ����:	��ջ�����������ص�'rc'��Ĵ�����
 * rc:		�Ĵ�������
 * opd:		������ָ��
 **********************************************************/
int load_1(int rc, Operand *opd)
{
	int r;	
	r = opd->r & SC_VALMASK;
	// ��Ҫ���ص��Ĵ����������
	// 1.ջ��������Ŀǰ��δ����Ĵ���
	// 2.ջ���������ѷ���Ĵ�������Ϊ��ֵ *p
	if (r >= SC_GLOBAL || 
		(opd->r & SC_LVAL) 
		) 
	{
		r = allocate_reg(rc);		
		load(r, opd);
	}
	opd->r = r;
    return r;
}

/*********************************************************** 
 * ����:	��ջ�����������ص�'rc1'��Ĵ���������ջ�����������ص�'rc2'��Ĵ���
 * rc1:		ջ�����������ص��ļĴ�������
 * rc2:		��ջ�����������ص��ļĴ�������
 **********************************************************/
void load_2(int rc1, int rc2)
{	
	load_1(rc2,optop);
	load_1(rc1,&optop[-1]);
}

/*********************************************************** 
 * ����:	��ջ�������������ջ����������
 **********************************************************/
void store0_1() 
{
	int r,t;
	r = load_1(REG_ANY,optop); 
	// ��ֵ����������ջ�У�������ص��Ĵ�����
	if ((optop[-1].r & SC_VALMASK) == SC_LLOCAL) 
	{
		Operand opd;
		t = allocate_reg(REG_ANY);
		operand_assign(&opd, T_INT, SC_LOCAL | SC_LVAL, optop[-1].value);
		load(t, &opd);
		optop[-1].r = t | SC_LVAL;
	}
    store(r, optop - 1);
    operand_swap();
    operand_pop(); 
}

/***********************************************************
 * ����:	�����꺯����ָ�/�ͷ�ջ,����__cdecl
 * val:		��Ҫ�ͷ�ջ�ռ��С(���ֽڼ�)
 **********************************************************/
void gen_addsp(int val)
{
	int opc = 0;
	if (val == (char)val) 
	{
		// ADD--Add	83 /0 ib	ADD r/m32,imm8	Add sign-extended imm8 from r/m32
		gen_opcode1(0x83);	// ADD esp,val
		gen_modrm(ADDR_REG,opc,REG_ESP,NULL,0);
        gen_byte(val);
    } 
	else 
	{
		// ADD--Add	81 /0 id	ADD r/m32,imm32	Add sign-extended imm32 to r/m32
		gen_opcode1(81);	// add esp, val
		gen_modrm(ADDR_REG,opc,REG_ESP,NULL,0);
		gen_dword(val);
    }
}

/***********************************************************
 * ����:	���ɺ�������ָ��
 **********************************************************/
void gen_call()
{
	int r;
    if ((optop->r & (SC_VALMASK | SC_LVAL)) == SC_GLOBAL) 
	{
		// ��¼�ض�λ��Ϣ
		coffreloc_add(sec_text, optop->sym, ind + 1, IMAGE_REL_I386_REL32);

		//	CALL--Call Procedure E8 cd   
		//	CALL rel32    call near,relative,displacement relative to next instrution
		gen_opcode1(0xe8); /* call im */
		gen_dword(optop->value - 4);
	} 
	else 
	{
        // FF /2 CALL r/m32 Call near, absolute indirect, address given in r/m32
        r = load_1(REG_ANY,optop);
        gen_opcode1(0xff);	// call/jmp *r
        gen_opcode1(0xd0 + r); //d0 = 11 010 000
    }
}

/*********************************************************** 
 * ����:	���ɺ������ô���,�Ƚ�������ջ��Ȼ��call
 * nb_args: ��������
 **********************************************************/
void gen_invoke(int nb_args)
{
    int size, r, args_size, i, func_call;
    
    args_size = 0;
	// ����������ջ
    for(i = 0;i < nb_args; i++) 
	{
		r = load_1(REG_ANY,optop);            
		size = 4;
		// PUSH--Push Word or Doubleword Onto the Stack
		// 50+rd	PUSH r32	Push r32
		gen_opcode1(0x50 + r);	// push r
		args_size += size;      
        operand_pop(); 
	}
	spill_regs();
	func_call = optop->type.ref->r;  // �õ�����Լ����ʽ
	gen_call();
	if (args_size && func_call != KW_STDCALL)
        gen_addsp(args_size);
    operand_pop();
}

/*********************************************************** 
 * ����:	����������Ԫ����
 * opc:		ModR/M [5:3]
 * op:		���������
 **********************************************************/
void gen_opi2(int opc,int op)
{
	int r, fr, c;
	if ((optop->r & (SC_VALMASK | SC_LVAL | SC_SYM)) == SC_GLOBAL)
	{
		r = load_1(REG_ANY,&optop[-1]);
		c = optop->value;
		if (c == (char)c) 
		{
			// ADC--Add with Carry			83 /2 ib	ADC r/m32,imm8	Add with CF sign-extended imm8 to r/m32
			// ADD--Add						83 /0 ib	ADD r/m32,imm8	Add sign-extended imm8 from r/m32
			// SUB--Subtract				83 /5 ib	SUB r/m32,imm8	Subtract sign-extended imm8 to r/m32
			// CMP--Compare Two Operands	83 /7 ib	CMP r/m32,imm8	Compare imm8 with r/m32
			gen_opcode1(0x83);
			gen_modrm(ADDR_REG,opc,r,NULL,0);
			gen_byte(c);
		} 
		else 
		{
			// ADD--Add					81 /0 id	ADD r/m32,imm32	Add sign-extended imm32 to r/m32
			// SUB--Subtract				81 /5 id	SUB r/m32,imm32	Subtract sign-extended imm32 from r/m32
			// CMP--Compare Two Operands	81 /7 id	CMP r/m32,imm32	Compare imm32 with r/m32
			gen_opcode1(0x81);
			gen_modrm(ADDR_REG,opc,r,NULL,0);
			gen_byte(c);
		}
	} 
	else 
	{
		load_2(REG_ANY, REG_ANY);
		r = optop[-1].r;
		fr = optop[0].r;

		// ADD--Add						01 /r	ADD r/m32,r32	Add r32 to r/m32
		// SUB--Subtract				29 /r	SUB r/m32,r32	Subtract r32 from r/m32
		// CMP--Compare Two Operands	39 /r	CMP r/m32,r32	Compare r32 with r/m32
		gen_opcode1((opc << 3) | 0x01);
		gen_modrm(ADDR_REG,fr,r,NULL,0);
	}
	operand_pop();
	if (op >= TK_EQ && op <= TK_GEQ) 
	{
		optop->r = SC_CMP;
		switch(op)
		{
		case TK_EQ:
			optop->value = 0x84;
			break;
		case TK_NEQ:
			optop->value = 0x85;
			break;
		case TK_LT:
			optop->value = 0x8c;
			break;
		case TK_LEQ:
			optop->value = 0x8e;
			break;
		case TK_GT:
			optop->value = 0x8f;
			break;
		case TK_GEQ:
			optop->value = 0x8d;
			break;
		}
	}  
}


/*********************************************************** 
 * ����:	������������
 * op:		���������
 **********************************************************/
void gen_opi(int op)
{
    int r, fr, opc;
	
    switch(op) 
	{
    case TK_PLUS:
        opc = 0;
		gen_opi2(opc,op);
		break;
	case TK_MINUS:
		opc = 5;
        gen_opi2(opc,op);
		break;
    case TK_STAR:
        load_2(REG_ANY, REG_ANY);
        r = optop[-1].r;
        fr = optop[0].r;
        operand_pop();

		// IMUL--Signed Multiply
		// 0F AF /r	IMULr32,r/m32	doubleword register <--doubleword register * r/m doubleword		
        gen_opcode2(0x0f,0xaf); /*imul  r, fr */
		gen_modrm(ADDR_REG,r,fr,NULL,0);
        break;
	case TK_DIVIDE:
	case TK_MOD:
		opc = 7;
        load_2(REG_EAX, REG_ECX);
        r = optop[-1].r;
        fr = optop[0].r;
        operand_pop();
        spill_reg(REG_EDX);

		// CWD/CDQ--Convert Word to Doubleword/Convert Doubleword to Qradword
		// 99	CWQ	EDX:EAX<--sign_entended EAX
		gen_opcode1(0x99);

		// IDIV--Signed Divide
		// F7 /7	IDIV r/m32	Signed divide EDX:EAX(where EDX must contain signed extension of EAX)
		// by r/m doubleword.(Result:EAX=Quotient, EDX=Remainder)
		// EDX:EAX������ r/m32����
		gen_opcode1(0xf7); /* idiv eax, fr*/
		gen_modrm(ADDR_REG,opc,fr,NULL,0);
		
        if (op == TK_MOD)
			r = REG_EDX;
        else
			r = REG_EAX;       
        optop->r = r;
        break;
	default:
        opc = 7;
        gen_opi2(opc,op);
		break;
	}
}


/***********************************************************
 * ����:	����t��ָ�����������
 * t:		ָ������
 **********************************************************/
Type *pointed_type(Type *t)
{
    return &t->ref->type;
}

/***********************************************************
 * ����:	����t��ָ����������ͳߴ�
 * t:		ָ������
 **********************************************************/
int pointed_size(Type *t)
{
    int align;
    return type_size(pointed_type(t), &align);
}

/*********************************************************** 
 * ����:	���ɶ�Ԫ����,��ָ�����������һЩ���⴦��
 * op:		���������
 **********************************************************/
void gen_op(int op)
{
	int u, bt1, bt2;
    Type type1;
	
    bt1 = optop[-1].type.t & T_BTYPE;
    bt2 = optop[0].type.t & T_BTYPE;
	
	if (bt1 == T_PTR || bt2 == T_PTR) 
	{
        if (op >= TK_EQ && op <= TK_GEQ) // ��ϵ����
		{
			gen_opi(op);
			optop->type.t = T_INT;
        }
		else if (bt1 == T_PTR && bt2 == T_PTR) //������������Ϊָ��
		{
            if (op != TK_MINUS)
                error("����ָ��ֻ�ܽ��й�ϵ���������");
            u = pointed_size(&optop[-1].type);
            gen_opi(op);
            optop->type.t = T_INT; 
            operand_push(&int_type, SC_GLOBAL, u);
            gen_op(TK_DIVIDE);
		} 
		else //����������һ����ָ�룬��һ������ָ�룬���ҷǹ�ϵ����
		{
            if (op != TK_MINUS && op != TK_PLUS) 
                error("ָ��ֻ�ܽ��й�ϵ��Ӽ�����");
            // ָ����Ϊ��һ������
            if (bt2 == T_PTR) 
			{
                operand_swap();
            }
            type1 = optop[-1].type;
            operand_push(&int_type, SC_GLOBAL, pointed_size(&optop[-1].type));
            gen_op(TK_STAR);
			
            gen_opi(op);			
            optop->type = type1;
        }
    }
	else
	{
		gen_opi(op);
		if (op >= TK_EQ && op <= TK_GEQ)
		{
			// ��ϵ������ΪT_INT����
			optop->type.t = T_INT;
		}
	}
}


/***********************************************************
 * ����:	�Ĵ������䣬�������Ĵ�����ռ��,�Ƚ������������ջ��
 * rc:		�Ĵ�������
 **********************************************************/
int allocate_reg(int rc)
{
    int r;
    Operand *p;
	int used;

    /* ���ҿ��еļĴ��� */
	for(r=0;r<=REG_EBX;r++) 
	{
        if (rc & REG_ANY || r == rc) 
		{
			used = 0;
            for(p=opstack;p<=optop;p++) 
			{
                if ((p->r & SC_VALMASK) == r)
                  used = 1;
            }
            if(used ==0) return r;
        }
    }
   
    // ���û�п��еļĴ������Ӳ�����ջ�׿�ʼ���ҵ���һ��ռ�õļĴ����ٳ���ջ��
    for(p=opstack;p<=optop;p++) 
	{
        r = p->r & SC_VALMASK;
        if (r < SC_GLOBAL && (rc & REG_ANY || r == rc)) 
		{
            spill_reg(r);
            return r;
        }
    }
    /* �˴���Զ�����ܵ��� */
    return -1;
}

/*********************************************************** 
 * ����:	���Ĵ���'r'������ڴ�ջ��,���ұ���ͷ�'r'�Ĵ����Ĳ�����Ϊ�ֲ�����
 * r:		�Ĵ�������
 **********************************************************/
void spill_reg(int r)
{
    int size, align;
    Operand *p, opd;
    Type *type;

    for(p=opstack;p<=optop;p++) 
	{
        if ((p->r & SC_VALMASK) == r) 
		{
			r = p->r & SC_VALMASK;
			type = &p->type;
			if (p->r & SC_LVAL)
				type = &int_type;
			size = type_size(type, &align);
			loc = calc_align(loc-size,align);
			operand_assign(&opd, type->t, SC_LOCAL | SC_LVAL, loc);
			store(r, &opd);
			if (p->r & SC_LVAL)
			{
				 p->r = (p->r & ~(SC_VALMASK)) | SC_LLOCAL; //��ʶ����������ջ��
			}
			else //sum = add(a = add(a,b),b = add(c,d));
			{
				p->r =  SC_LOCAL | SC_LVAL;				
			}
			p->value = loc;
			break;
        }
    }
}

/*********************************************************** 
 * ����:	��ռ�õļĴ���ȫ�������ջ�� 
 **********************************************************/
void spill_regs()
{
    int r;
    Operand *p;
    for(p = opstack;p <= optop; p++) 
	{
        r = p->r & SC_VALMASK;
        if (r < SC_GLOBAL) 
		{
            spill_reg(r);
        }
    }
}

/*********************************************************** 
 * ����:	������ߵ�ַ��תָ���ת��ַ����
 * t:		ǰһ��תָ���ַ
 **********************************************************/
int gen_jmpforward(int t)
{
	// JMP--Jump		
	// E9 cd	JMP rel32	Jump near,relative,displacement relative to next instruction
	gen_opcode1(0xe9);
    return makelist(t);;
}

/*********************************************************** 
 * ����:	������͵�ַ��תָ���ת��ַ��ȷ��
 * a:		��ת����Ŀ���ַ
 **********************************************************/
void gen_jmpbackword(int a)
{
    int r;
    r = a - ind - 2;
    if (r == (char)r) 
	{
		// EB cb	JMP rel8	Jump short,relative,displacement relative to next instruction
        gen_opcode1(0xeb);
        gen_byte(r);
    } 
	else 
	{
		// E9 cd	JMP rel32	Jump short,relative,displacement relative to next instruction
		gen_opcode1(0xe9);
		gen_dword(a - ind - 4);
    }
}

/*********************************************************** 
 * ����:	����������תָ��
 * t:		ǰһ��תָ���ַ
 * ����ֵ:  ����תָ���ַ
 **********************************************************/
int gen_jcc(int t)
{
    int v;
	int inv = 1;

    v = optop->r & SC_VALMASK;
    if (v == SC_CMP)
	{
		// Jcc--Jump if Condition Is Met
		// .....
		// 0F 8F cw/cd		JG rel16/32	jump near if greater(ZF=0 and SF=OF)
		// .....
		gen_opcode2(0x0f,optop->value ^ inv);
		t = makelist(t);
    } 
	else 
	{		
        if ((optop->r & (SC_VALMASK | SC_LVAL | SC_SYM)) == SC_GLOBAL) 
		{

                t = gen_jmpforward(t);			
        } 
		else 
		{
            v = load_1(REG_ANY,optop); 

			// TEST--Logical Compare
			// 85 /r	TEST r/m32,r32	AND r32 with r/m32,set SF,ZF,PF according to result		
			gen_opcode1(0x85);
			gen_modrm(ADDR_REG,v,v,NULL,0);
			
			//  Jcc--Jump if Condition Is Met
			// .....
			// 0F 8F cw/cd		JG rel16/32	jump near if greater(ZF=0 and SF=OF)
			// .....
			gen_opcode2(0x0f,0x85 ^ inv);
			t = makelist(t);		
        }
    }
    operand_pop();
    return t;
}

/***********************************************************
 * ����:		���ɺ�����ͷ����
 * func_type:	��������
 **********************************************************/
void gen_prolog(Type *func_type)
{
    int addr, align, size, func_call;
    int param_addr;
    Symbol *sym;
    Type *type;

    sym = func_type->ref;
    func_call = sym->r;
    addr = 8;
    loc = 0;
    
	func_begin_ind = ind;  //��¼�˺����忪ʼ���Ա㺯�������ʱ��亯��ͷ����Ϊ��ʱ����ȷ�����ٵ�ջ��С
    ind += FUNC_PROLOG_SIZE;
	if(sym->type.t == T_STRUCT)
		error("��֧�ַ��ؽṹ�壬���Է��ؽṹ��ָ��");
    //  ��������
    while ((sym = sym->next) != NULL) 
	{
        type = &sym->type;
        size = type_size(type, &align);
        size = calc_align(size,4); //�˾�ǳ���Ҫ����Ϊ����ѹջ����4�ֽڶ���ģ����Դ˴�ÿ����������4�ֽڶ���
        //  �ṹ����Ϊָ�봫��
        if ((type->t & T_BTYPE) == T_STRUCT) 
		{
            size = 4;
        }

        param_addr = addr;
        addr += size;
      
        sym_push(sym->v & ~SC_PARAMS, type,
                 SC_LOCAL | SC_LVAL, param_addr);
    }
    func_ret_sub = 0;
    //  __stdcall����Լ�������������������ջ
    if (func_call == KW_STDCALL)
        func_ret_sub = addr - 8;
}

/***********************************************************
 * ����:	���ɺ�����β����
 **********************************************************/
void gen_epilog()
{
	int v, saved_ind,opc;

	// 8B /r	mov r32,r/m32	mov r/m32 to r32
	gen_opcode1(0x8b);/* mov esp, ebp*/	
	gen_modrm(ADDR_REG,REG_ESP,REG_EBP,NULL,0); 
	
	// POP--Pop a Value from the Stack
	// 58+	rd		POP r32		POP top of stack into r32; increment stack pointer
	gen_opcode1(0x58+REG_EBP);  /*pop ebp*/

    if (func_ret_sub == 0) 
	{
		// RET--Return from Procedure
		// C3	RET	near return to calling procedure
        gen_opcode1(0xc3); // ret
    } 
	else 
	{
		// RET--Return from Procedure
		// C2 iw	RET imm16	near return to calling procedure and pop imm16 bytes form stack
        gen_opcode1(0xc2);	// ret n
        gen_byte(func_ret_sub);
        gen_byte(func_ret_sub >> 8);
    }
    
	v= calc_align(-loc,4);
    saved_ind = ind;
    ind = func_begin_ind; // - FUNC_PROLOG_SIZE;

	// PUSH--Push Word or Doubleword Onto the Stack
	// 50+rd	PUSH r32	Push r32
    gen_opcode1(0x50+REG_EBP);	// push ebp 

	// 89 /r	MOV r/m32,r32	Move r32 to r/m32
	gen_opcode1(0x89); //  mov ebp, esp
	gen_modrm(ADDR_REG,REG_ESP,REG_EBP,NULL,0);

	//SUB--Subtract		81 /5 id	SUB r/m32,imm32	Subtract sign-extended imm32 from r/m32
	gen_opcode1(0x81);	// sub esp, stacksize
	opc = 5;
	gen_modrm(ADDR_REG,opc,REG_ESP,NULL,0);
    gen_dword(v);
    ind = saved_ind;
}

/***********************************************************
 * ����:	������ʼ��
 * type:	��������
 * sec:		�������ڽ�
 * c:		�������ֵ
 * v:		�������ű��
 **********************************************************/
void init_variable(Type *type, Section *sec, int c, int v)
{
    int bt;
    void *ptr;

    if (sec) 
	{                                                       
        if ((optop->r & (SC_VALMASK | SC_LVAL)) != SC_GLOBAL)                                             
             error("ȫ�ֱ��������ó�����ʼ��");  

        bt = type->t & T_BTYPE;
        ptr = sec->data + c;
     
        switch(bt) 
		{
		case T_CHAR:
			*(char *)ptr = optop->value; // ������char g_cc = 'a';	printf("g_cc=%c\n",g_cc);
            break; 
		case T_SHORT:
			*(short *)ptr = optop->value; // ������short g_ss = 1234;	printf("g_ss=%d\n",g_ss);
            break;    
        default:
            if (optop->r & SC_SYM) 
			{
				coffreloc_add(sec, optop->sym, c, IMAGE_REL_I386_DIR32);	// ������char *g_pstr = "g_pstr_Hello";
            }
            *(int *)ptr = optop->value;
            break;
        }
        operand_pop();
    } 
	else 
	{
		if(type->t&T_ARRAY)
		{
			operand_push(type,SC_LOCAL|SC_LVAL,c);
			operand_swap();
			spill_reg(REG_ECX);

			// B8+ rd	mov r32,imm32		mov imm32 to r32
			gen_opcode1(0xB8+REG_ECX);//move ecx,n
			gen_dword(optop->type.ref->c);  
			gen_opcode1(0xB8+REG_ESI);
			gen_addr32(optop->r,optop->sym,optop->value); // move esi <- 
			operand_swap();

			// LEA--Load Effective Address
			// 8D /r	LEA r32,m	Store effective address for m in register r32
			gen_opcode1(0x8D);
			gen_modrm(ADDR_OTHER,REG_EDI,SC_LOCAL,optop->sym,optop->value); // lea edi, [ebp-n]

			// Instruction prefix	F3H--REPE/REPZ prefix(used only with string instructions)
			gen_prefix(0xf3);//rep movs byte

			// MOVS/MOVSB/MOVSW/MOVSD--Move Data from String to String
			// A4	MOVSB	Move byte at address DS:(E)SI to address ES:(E)SI
			gen_opcode1(0xA4); 
			optop -= 2;
		}
		else
		{
			operand_push(type, SC_LOCAL|SC_LVAL, c);
			operand_swap();
			store0_1();
			operand_pop();
		}
    }
}


/***********************************************************
 * ����:		����洢�ռ�
 * type:		��������
 * r:			�����洢����
 * has_init:	�Ƿ���Ҫ���г�ʼ��
 * v:			�������ű��
 * addr(���):  �����洢��ַ
 * ����ֵ:		�����洢��
 **********************************************************/
Section *allocate_storage(Type *type, int r, int has_init, int v, int *addr)
{
    int size, align;
    Section *sec = NULL;
    size = type_size(type,&align);

	if (size < 0)
	{
		if(type->t&T_ARRAY && type->ref->type.t == T_CHAR)
		{
			type->ref->c = strlen((char*)tkstr.data) + 1;
			size = type_size(type, &align);
		}
	    else
            error("���ͳߴ�δ֪");  
    }
	
	// �ֲ�������ջ�з���洢�ռ�
	if ((r & SC_VALMASK) == SC_LOCAL) 
	{
		loc = calc_align(loc-size,align);
        *addr = loc;
    } 
	else 
	{
		
		if (has_init == 1)		// ��ʼ����ȫ�ֱ�����.data�ڷ���洢�ռ�
			sec = sec_data;		
		else if(has_init == 2)	// �ַ���������.rdata�ڷ���洢�ռ�
			sec = sec_rdata;		
		else					// δ��ʼ����ȫ�ֱ�����.bss�ڷ���洢�ռ�
			sec = sec_bss;		
		
		sec->data_offset = calc_align(sec->data_offset,align);
		*addr = sec->data_offset;
		sec->data_offset += size;

		// Ϊ��Ҫ��ʼ���������ڽ��з���洢�ռ�
		if (sec->sh.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA && 
			sec->data_offset > sec->data_allocated)
			section_realloc(sec, sec->data_offset);	
		
		if (v==0) //�����ַ���
		{
            operand_push(type, SC_GLOBAL | SC_SYM, *addr);
            optop->sym = sym_sec_rdata;
        }
	} 
	return sec;
}



