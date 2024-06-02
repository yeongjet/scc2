// ���Լ�����д��������������������Դ����

#include "scc.h"

/***********************************************************
 *  ����:		���·��䶯̬��������
 *  parr:		��̬����ָ��
 *  new_size:	��̬��������Ԫ�ظ���
 **********************************************************/
void dynarray_realloc(DynArray *parr, int new_size)
{
    int capacity;
    void *data;

    capacity = parr->capacity;
    while (capacity < new_size)
        capacity = capacity * 2;
    data = realloc(parr->data, capacity);
    if (!data)
        error("�ڴ����ʧ��");
    parr->capacity = capacity;
    parr->data = data;
}

/***********************************************************
 *  ����:	׷�Ӷ�̬����Ԫ��
 *  parr:	��̬����ָ��
 *  data:	��Ҫ׷�ӵ���Ԫ��
 **********************************************************/
void dynarray_add(DynArray *parr, void *data)
{
 	int count;
    count = parr->count + 1;
    if (count*sizeof(void*) > parr->capacity)
        dynarray_realloc(parr, count*sizeof(void*));
    parr->data[count - 1] = data;
    parr->count = count;  
}

/***********************************************************
 * ����:		��ʼ����̬���鴢������
 * parr:		��̬����ָ��
 * initsize:	��̬�����ʼ������ռ�
 **********************************************************/
void dynarray_init(DynArray *parr, int initsize)
{
	if(parr != NULL)
	{
		parr->data = (void**)malloc(sizeof(void*)*initsize);
		parr->count = 0;
		parr->capacity = initsize;
	}
}


/***********************************************************
 *  ����:	�ͷŶ�̬����ʹ�õ��ڴ�ռ�
 *  parr:	��̬����ָ��
 **********************************************************/
void dynarray_free(DynArray *parr)
{
    void **p;
    for (p = parr->data; parr->count; ++p, --parr->count)
        if (*p)
            free(*p);
    free(parr->data);
    parr->data = NULL;
}

/***********************************************************
 *  ����:	��̬����Ԫ�ز���
 *  parr:	��̬����ָ��
 *  key:	Ҫ���ҵ�Ԫ��
 **********************************************************/                                             
int dynarray_search(DynArray *parr, int key)
{                                            
    int i;
   	int **p;
	p = (int**)parr->data;
    for (i = 0; i < parr->count; ++i, p++)            
    if (key == **p)                
        return i;                            
    return -1;                               
}         