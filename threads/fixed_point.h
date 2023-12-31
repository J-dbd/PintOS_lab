#include <stdio.h>

#define F (1 << 14)     //fixed point 1 

// x and y denote fixed_point numbers in 17.14 format 
// n is an integer

/* integer를 fixed point로 전환 */
int int_to_fp(int n);          

/* FP를 int로 전환(반올림) */
int fp_to_int_round(int x);     

/* FP를 int로 전환(버림) */
int fp_to_int(int x);           

/* FP의 덧셈 */
int add_fp(int x, int y);       

/* FP와 int의 덧셈  */
int add_mixed(int fp, int int_n);    

/* FP의 뺄셈(x-y) */
int sub_fp(int x, int y);     

/* FP와 int의 뺄셈(x-n) */
int sub_mixed(int x, int n);    

/* FP의 곱셈 */
int mult_fp(int x, int y);      

/* FP와 int의 곱셈 */
int mult_mixed(int x, int y);   

/* FP의 나눗셈(x/y) */
int div_fp(int x, int y);       

/* FP와 int 나눗셈(x/n) */
int div_mixed(int x, int n);    

///////////////////////////////
// 나누기는 무조건 실수 ////

int int_to_fp(int n) {
    return n * F;
}

int fp_to_int_round(int x) {
    if (x >= 0) return (x + F / 2) / F;
    else return (x - F / 2) / F;
}

int fp_to_int(int x) {
    return x / F;
}

int add_fp(int x, int y) {
    return x + y;
}

int sub_fp(int x, int y) {
    return x - y;
}

int add_mixed(int x, int n) {
    return x + n * F;
}

int sub_mixed(int x, int n) {
    return x - n * F;
}

int mult_fp(int x, int y) {
    return ((int64_t) x) * y / F;
}

int mult_mixed(int x, int n) {
    return x * n;
}

int div_fp(int x, int y) {
    return ((int64_t) x) * F / y;
}

int div_mixed(int x, int n) {
    return x / n;
}  


