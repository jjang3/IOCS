#include <stdio.h>

// A function that takes two arrays and returns the sum of their first elements
// This approach encourages the compiler to use SIMD when optimized
int compute_sum(int *a, int *b, int size) {
    int result = 0;
    for (int i = 0; i < size; i++) {
        result += a[i] + b[i];  // Loop over arrays for better SIMD optimization
    }

    // Print result for the first pair of elements
    printf("Sum of %d and %d is %d\n", a[0], b[0], result);
    return result;
}

int main() {
    int local_var1[4], local_var2[4];

    // Input values for local_var1 and local_var2
    printf("Enter value for local_var1: ");
    scanf("%d", &local_var1[0]);

    printf("Enter value for local_var2: ");
    scanf("%d", &local_var2[0]);

    // Initialize arrays for SIMD-friendly behavior
    for (int i = 1; i < 4; i++) {
        local_var1[i] = local_var1[0];  // Replicate values for simplicity
        local_var2[i] = local_var2[0];
    }

    // Call compute_sum with dynamic input values
    int sum_result = compute_sum(local_var1, local_var2, 4);

    // Perform another operation
    int final_result = sum_result * 2;

    printf("Final result: %d\n", final_result);

    return 0;
}

void foo()
{
    int c[4] = {17, 17, 17, 17};
    int d[4] = {71, 71, 71, 71};
    int second_result = compute_sum(c, d, 4);
}
