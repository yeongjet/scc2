/***********************************************************
 * HelloWorld.cԴ�ļ�
 **********************************************************/
int a, b, c;
int main()
{
    printf("Hello World!\n");
    return 0;
}

void _entry()
{
    int ret;
    ret = main();
    exit(ret);
}
