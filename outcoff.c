// ���Լ�����д��������������������Դ����

#include "scc.h"
DynArray sections;			// ������

Section *sec_text,			// �����
		*sec_data,			// ���ݽ�
		*sec_bss,			// δ��ʼ�����ݽ�
		*sec_idata,			// ������
		*sec_rdata,			// ֻ�����ݽ�
		*sec_rel,			// �ض�λ��Ϣ��
		*sec_symtab,		// ���ű��	
		*sec_dynsymtab;		// ���ӿ���Ž�

int nsec_image;				// ӳ���ļ��ڸ���

/*********************************************************** 
 * ����:		�����������·����ڴ�,�������ݳ�ʼ��Ϊ0
 * sec:			���·����ڴ�Ľ�
 * new_size:	�������³���
 **********************************************************/
void section_realloc(Section *sec, int new_size)
{
    int size;
    char *data;
    
    size = sec->data_allocated;
    while (size < new_size)
        size = size * 2;
    data = realloc(sec->data, size);
    if (!data)
        error("�ڴ����ʧ��");
    memset(data + sec->data_allocated, 0, size - sec->data_allocated);/* �·�����ڴ����ݳ�ʼ��Ϊ0 */ 
    sec->data = data;
    sec->data_allocated = size;
}

/***********************************************************
 * ����:		��������Ԥ������increment��С���ڴ�ռ�
 * sec:			Ԥ���ڴ�ռ�Ľ�
 * increment:	Ԥ���Ŀռ��С
 * ����ֵ:		Ԥ���ڴ�ռ���׵�ַ
 **********************************************************/
void *section_ptr_add(Section *sec, int increment)
{
    int offset, offset1;
    offset = sec->data_offset;
    offset1 = offset + increment;
    if (offset1 > sec->data_allocated)
        section_realloc(sec, offset1);
    sec->data_offset = offset1;
    return sec->data + offset;
}

/*********************************************************** 
 * ����:			�½���
 * name:			������
 * Characteristics:	������
 * ����ֵ:			�����ӽ�
 **********************************************************/
Section * section_new(char *name, int Characteristics)
{
	Section *sec;
	int initsize = 8;
	sec = mallocz(sizeof(Section));
	strcpy(sec->sh.Name,name);
	sec->sh.Characteristics = Characteristics;
	sec->index = sections.count + 1; //one-based index
    sec->data = mallocz(sizeof(char)*initsize);
	sec->data_allocated = initsize;
	if(!(Characteristics & IMAGE_SCN_LNK_REMOVE))
		nsec_image++;
    dynarray_add(&sections, sec);
	return sec;
}

/*********************************************************** 
 * ����:	����COFF����
 * symtab:	����COFF���ű�Ľ�
 * name:	��������
 * ����ֵ:	����COFF���ű������
 **********************************************************/
int coffsym_search(Section *symtab,char *name)
{
	CoffSym *cfsym;
 	int cs,keyno;
	char *csname;
	Section *strtab;
    
	keyno = elf_hash(name);
	strtab = symtab->link;
	cs = symtab->hashtab[keyno];	
	while(cs)
	{	
		cfsym = (CoffSym*)symtab->data+cs;
		csname = strtab->data + cfsym->Name;
		/*�˴������stricmp�ⲿ���õĺ���Դ�����пɲ����ִ�Сд�������ɵ�pe�����õĺ������ƴ�Сд������ȷ��
		  ����:printf��дΪPrintf�������н����Ȼ����ȷ��,�˴���ô���˿�����Щ���⣬����elf_hash��ϣ��������ĸ
		  ���ִ�Сд�����printf��PrintF�Ĺ�ϣֵ��ͬ�������������⣬����˴�Ҫ�ģ����뽫��ϣ������Ϊ�����ִ�Сд��
		  ���ڹ�ϣ�����Ŀ�ͷ��_strupr����һ��
		*/
		if(!strcmp(name,csname)) 	
    		return cs;
		cs = cfsym->Next;
	}
	return cs;
}


/*********************************************************** 
 * ����:	����COFF�������ַ���
 * strtab:	����COFF�ַ�����Ľ�
 * name:	���������ַ���
 * ����ֵ:	����COFF�ַ���
 **********************************************************/
char *coffstr_add(Section *strtab,char* name)
{	
	int len;
	char *pstr;
	len = strlen(name);
	pstr = section_ptr_add(strtab, len+1);
	memcpy(pstr,name,len);
	return pstr;
}

/*********************************************************** 
 * ����:			����COFF����
 * symtab:			����COFF���ű�Ľ�
 * name:			��������
 * val:				�������ص�ֵ
 * sec_index:		����˷��ŵĽ�
 * type:			Coff��������
 * StorageClass:	Coff���Ŵ洢���	
 * ����ֵ:			����COFF���ű������
 **********************************************************/
int coffsym_add(Section *symtab,char* name, int val, int sec_index,
							short type, char StorageClass)
{
    CoffSym *cfsym;
	int cs,keyno;
	char *csname;
	Section *strtab = symtab->link;
	int *hashtab;
    hashtab = symtab->hashtab;
	cs = coffsym_search(symtab,name);
	if(cs == 0)
	{		
        cfsym = section_ptr_add(symtab, sizeof(CoffSym));
		csname = coffstr_add(strtab, name);
		cfsym->Name = csname - strtab->data;
		cfsym->Value =	val;
		cfsym->Section = sec_index;
		cfsym->Type = type;
		cfsym->StorageClass = StorageClass;
		cfsym->Value =	val;
		keyno = elf_hash(name);
		cfsym->Next = hashtab[keyno];

		cs = cfsym - (CoffSym*)symtab->data;	
		hashtab[keyno] = cs;
	}
	return cs;
}

/***********************************************************
 * ����:			���ӻ����COFF����,����ֻ�����ں�����������������
 * s:				����ָ��
 * val:				����ֵ
 * sec_index:		����˷��ŵĽ�
 * type:			Coff��������
 * StorageClass:	Coff���Ŵ洢���
 **********************************************************/
void coffsym_add_update(Symbol *s, int val, int sec_index,
					short type, char StorageClass) 
{
	char *name; 
	CoffSym *cfsym;
	if (!s->c) 
	{   
		name = ((TkWord*)tktable.data[s->v])->spelling; 
		s->c = coffsym_add(sec_symtab,name,val,sec_index,type,StorageClass);
	}
	else //��������������
	{
		cfsym = &((CoffSym *)sec_symtab->data)[s->c];
        cfsym->Value = val;
        cfsym->Section = sec_index;
	}
}

/***********************************************************
 * ����:	�ͷ����н�����
 **********************************************************/
void free_sections()
{
	int i;
	Section *sec;
	for(i = 0; i < sections.count; i++)
	{
		sec = (Section*)sections.data[i];
		if(sec->hashtab != NULL)
			free(sec->hashtab);  
		free(sec->data);
	}
	dynarray_free(&sections);
}

/***********************************************************
 * ��Ҫ��һ�·��ű�Ĵ洢�ṹ���ڴ�洢�ṹ���ļ��洢�ṹ
 * ����:			�½��洢COFF���ű�Ľ�
 * symtab:			COFF���ű���
 * Characteristics: ������
 * strtab_name:		����ű���ص��ַ�����
 * ����ֵ:			�洢COFF���ű�Ľ�
 **********************************************************/
Section *new_coffsym_section(char *symtab_name, int Characteristics, char *strtab_name)
{
	Section *sec;
	sec = section_new(symtab_name, Characteristics);
	sec->link = section_new(strtab_name, Characteristics);
	sec->hashtab = mallocz(sizeof(int)*MAXKEY);
	return sec;
}

/*********************************************************** 
 * ����:	����COFF�ض�λ��Ϣ
 * offset:	��Ҫ�����ض�λ�Ĵ��������������Ӧ�ڵ�ƫ��λ��
 * cfsym:	���ű������
 * section: �������ڽڣ��ص㽲һ����Coff����
 * type:	�ض�λ����
 **********************************************************/
void coffreloc_direct_add(int offset, int cfsym, char section, char type)
{
	CoffReloc *rel;
	rel = section_ptr_add(sec_rel, sizeof(CoffReloc));
    rel->offset = offset;
	rel->cfsym = cfsym;
	rel->section = section;
    rel->type = type;
}

/*********************************************************** 
 * ����:	�����ض�λ��Ŀ
 * section: �������ڽ�
 * sym:		����ָ��
 * offset:	��Ҫ�����ض�λ�Ĵ��������������Ӧ�ڵ�ƫ��λ��
 * type:	�ض�λ����
 **********************************************************/
void coffreloc_add(Section *sec, Symbol *sym, int offset, char type)
{
	int cfsym;
	char *name;
	if (!sym->c) 
		coffsym_add_update(sym, 0,IMAGE_SYM_UNDEFINED, CST_FUNC, IMAGE_SYM_CLASS_EXTERNAL);
	name = ((TkWord*)tktable.data[sym->v])->spelling;
	cfsym = coffsym_search(sec_symtab,name);
    coffreloc_direct_add(offset, cfsym, sec->index,type);
}

/***********************************************************
 * ����:	COFF��ʼ��
 **********************************************************/
void init_coff()
{
	dynarray_init(&sections,8);
    nsec_image = 0;

	sec_text = section_new(".text",
				IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE);
	sec_data = section_new(".data",
				IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
				IMAGE_SCN_CNT_INITIALIZED_DATA);
	sec_rdata = section_new(".rdata",
				IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);
	sec_idata = section_new(".idata",
				IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 
				IMAGE_SCN_CNT_INITIALIZED_DATA);
	sec_bss = section_new(".bss",
				IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 
				IMAGE_SCN_CNT_UNINITIALIZED_DATA);
	sec_rel = section_new(".rel",
				IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_MEM_READ);


	sec_symtab = new_coffsym_section(".symtab",
				IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_MEM_READ,".strtab");

	sec_dynsymtab = new_coffsym_section(".dynsym",
				IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_MEM_READ,".dynstr");

	coffsym_add(sec_symtab,"",0,0,0,IMAGE_SYM_CLASS_NULL);
	coffsym_add(sec_symtab,".data",0,sec_data->index,0,IMAGE_SYM_CLASS_STATIC);
	coffsym_add(sec_symtab,".bss",0,sec_bss->index,0,IMAGE_SYM_CLASS_STATIC);
	coffsym_add(sec_symtab,".rdata",0,sec_rdata->index,0,IMAGE_SYM_CLASS_STATIC);
	coffsym_add(sec_dynsymtab,"",0,0,0,IMAGE_SYM_CLASS_NULL);
}

/***********************************************************
 * ����:	�ӵ�ǰ��дλ�õ�new_posλ����0��ļ�����
 * fp:		�ļ�ָ��
 * new_pos: ��յ�λ��
 **********************************************************/
void fpad(FILE *fp, int new_pos)
{
    int curpos = ftell(fp);
    while (++curpos <= new_pos)
        fputc(0, fp);
}

/***********************************************************
 * ����:	���Ŀ���ļ�
 * name:	Ŀ���ļ���
 **********************************************************/
void write_obj(char *name)
{
	int file_offset;
	FILE *fout = fopen(name,"wb");
	int i,sh_size,nsec_obj=0;
    IMAGE_FILE_HEADER *fh;

	nsec_obj = sections.count - 2;
    sh_size = sizeof(IMAGE_SECTION_HEADER); 
	file_offset = sizeof(IMAGE_FILE_HEADER)+nsec_obj*sh_size;
	fpad(fout,file_offset);
	fh = mallocz(sizeof(IMAGE_FILE_HEADER));
	for(i = 0; i < nsec_obj; i++)
	{
		Section *sec = (Section*)sections.data[i];
		if(sec->data == NULL) continue;
		fwrite(sec->data,1,sec->data_offset,fout);
		sec->sh.PointerToRawData = file_offset;
		sec->sh.SizeOfRawData = sec->data_offset;
		file_offset += sec->data_offset;
	}
	fseek(fout, SEEK_SET, 0);
	fh->Machine = IMAGE_FILE_MACHINE_I386;
	fh->NumberOfSections = nsec_obj;
	fh->PointerToSymbolTable = sec_symtab->sh.PointerToRawData;
	fh->NumberOfSymbols = sec_symtab->sh.SizeOfRawData/sizeof(CoffSym);
	fwrite(fh,1,sizeof(IMAGE_FILE_HEADER),fout);
	for(i = 0; i < nsec_obj; i++)
	{
		Section *sec = (Section*)sections.data[i];
		fwrite(sec->sh.Name,1,sh_size,fout);
	}

	free(fh);
	fclose(fout);	
}