#ifndef _USER_LOADER_H
#define _USER_LOADER_H



#include <stdio.h>


void _init(void)__attribute__((section(".mytext")));
void _print_constructor()__attribute__((section(".mytext")));

void _print_constructor()__attribute__((constructor));


void print_start(void);

void start_load(void);



#endif