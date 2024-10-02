#include <stdio.h>

// A function that takes two arguments and returns their sum
int compute_sum(int a, int b) {
    int result = a + b;
    printf("Sum of %d and %d is %d\n", a, b, result);
    return result;
}

int main() {
    int local_var1, local_var2;

    // Input values for local_var1 and local_var2
    printf("Enter value for local_var1: ");
    scanf("%d", &local_var1);

    printf("Enter value for local_var2: ");
    scanf("%d", &local_var2);

    // Call compute_sum with dynamic input values
    int sum_result = compute_sum(local_var1, local_var2);

    // Perform another operation
    int final_result = sum_result * 2;

    printf("Final result: %d\n", final_result);

    return 0;
}


void foo()
{
    int c = 17;
    int d = 71;
    int second_result = compute_sum(c, d);
}


