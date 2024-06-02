// ���Լ�����д��������������������Դ����

#include "scc.h"

FILE *fin = NULL;				// Դ�ļ�ָ��
char *filename;					// Դ�ļ�����
DynArray src_files;				// Դ�ļ�����
char *outfile;					// ����ļ���
int output_type;				// ����ļ�����
float scc_version = 1.00;		// SCC�������汾��

/*********************************************************** 
 * ����:	������ڴ沢�����ݳ�ʼ��Ϊ'0'
 * size:	�����ڴ��С
 **********************************************************/
void *mallocz(int size)
{
    void *ptr;
	ptr = malloc(size);
	if (!ptr && size)
        error("�ڴ����ʧ��");
    memset(ptr, 0, size);
    return ptr;
}

/*********************************************************** 
 * ����:	�����ϣ��ַ
 * key:		��ϣ�ؼ���
 * MAXKEY:	��ϣ����
 **********************************************************/
int elf_hash(char *key)
{
    int h = 0, g;
    while (*key) 
	{
        h = (h << 4) + *key++;
        g = h & 0xf0000000;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }
    return h % MAXKEY;
}

/*********************************************************** 
 * ����:	�����ֽڶ���λ��
 * n:		δ����ǰֵ
 * align:   ��������
 **********************************************************/
int calc_align(int n, int align)
{                                                     
    return ((n + align - 1) & (~(align - 1)));        
}


/***********************************************************
 * ����:	��ʼ��
 **********************************************************/
void init ()
{
	dynarray_init(&src_files,1);
	dynarray_init(&array_lib,4);
	dynarray_init(&array_dll,4);
    init_lex();

	syntax_state = SNTX_NUL;
	syntax_level = 0;

   	stack_init(&local_sym_stack,8);
	stack_init(&global_sym_stack,8);
	sym_sec_rdata = sec_sym_put(".rdata",0);

	int_type.t = T_INT;
    char_pointer_type.t = T_CHAR;
    mk_pointer(&char_pointer_type);
	default_func_type.t = T_FUNC;
	default_func_type.ref = sym_push(SC_ANOM, &int_type, KW_CDECL, 0);

	optop = opstack - 1;
    
	init_coff();	

	lib_path = get_lib_path();
}

/*********************************************************** 
 * ����:	ɨβ������
 **********************************************************/
void cleanup()
{	
	int i;
    sym_pop(&global_sym_stack, NULL);
	stack_destroy(&local_sym_stack);
	stack_destroy(&global_sym_stack);
	free_sections();
    
	for(i = TK_IDENT; i < tktable.count; i++)
	{	
        free(tktable.data[i]);	//tktable�����TK_IDENT�����ͷţ��������dynarray_free�������⣬��ΪTK_IDENT���µ�tokenû�з��ڶ��У����Ƿ��ھ�̬�洢��

	}
    free(tktable.data);
	dynarray_free(&array_dll);
	free(src_files.data);
	free(array_lib.data);
}

/*********************************************************** 
 * ����:	����������ѡ��
 * argc:	�����в�������
 * argv:	�����в�������
 **********************************************************/
int process_command(int argc, char **argv)
{
	int i;
	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
			char *p = &argv[i][1];
			int c = *p;
			switch(c)
			{
				case 'o':
					outfile = argv[++i];
					break;
				case 'c':
					dynarray_add(&src_files, argv[++i]);
					output_type = OUTPUT_OBJ;
					return 1;
				case 'l':
					dynarray_add(&array_lib, &argv[i][2]);
					break;
				case 'G':
					subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
					break;
				case 'v':
					printf("SCC Version %.2f",scc_version);
					return 0;
				case 'h':
					printf("usage: scc [-c infile] [-o outfile] [-llib] [infile1 infile2...] \n");
					return 0;
				default:
					printf("unsupported command line option");
					return 0;
			}
		}
		else
		{
			dynarray_add(&src_files, argv[i]);
		}

	}
	return 1;
		
}

/***********************************************************
 * ����:	�õ��ļ���չ��
 * fname:	�ļ�����
 **********************************************************/
char *get_file_ext(char *fname)
{
	char *p;
	p = strrchr(fname,'.');
	return p+1;
}

/*********************************************************** 
 * ����:	����SCԴ�ļ�
 * fname:	SCԴ�ļ���
 **********************************************************/
void compile(char *fname)
{
    fin = fopen(fname,"rb");
	if(!fin)
		printf("cannot open SC source file");
	getch();
	line_num = 1;
	get_token();
	translation_unit();
	fclose(fin);
	printf("\n\n%s ��������: %d��\n\n",fname,line_num);
}

/*********************************************************** 
 * ����:	main������
 **********************************************************/
void main(int argc, char ** argv)
{  
	int i,opind;
	char *ext;
	init();
	output_type = OUTPUT_EXE;
	subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
	opind = process_command(argc,argv);
	if(opind == 0)
		return;
	for (i = 0; i < src_files.count; i++)
	{
		filename = src_files.data[i];
		ext = get_file_ext(filename);
		if(!strcmp(ext,"c"))
			compile(filename);
		if(!strcmp(ext,"obj"))
			load_obj_file(filename);
	}
	if(output_type == OUTPUT_OBJ)
		write_obj(outfile); 
	else
		pe_output_file(outfile);

	cleanup();	
}