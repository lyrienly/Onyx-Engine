#include <stdio.h>
#include <math.h>

float fd;

int
test()
{

   if (fd < 5.5) {
     return 1;
   } else {
     return 0;
   }
}

int main()
{

   float a = 12.34 + 56.78;
   printf("%f\n", a);

   printf("%f\n", 12.34 + 56.78);
   printf("%f\n", 12.34 - 56.78);
   printf("%f\n", 12.34 * 56.78);
   printf("%f\n", 12.34 / 56.78);

   printf("%d %d %d %d %d %d\n", 12.34 < 56.78, 12.34 <= 56.78, 12.34 == 56.78, 12.34 >= 56.78, 12.34 > 56.78, 12.34 != 56.78);
   printf("%d %d %d %d %d %d\n", 12.34 < 12.34, 12.34 <= 12.34, 12.34 == 12.34, 12.34 >= 12.34, 12.34 > 12.34, 12.34 != 12.34);
   printf("%d %d %d %d %d %d\n", 56.78 < 12.34, 56.78 <= 12.34, 56.78 == 12.34, 56.78 >= 12.34, 56.78 > 12.34, 56.78 != 12.34);

   a = 12.34;
   a += 56.78;
   printf("%f\n", a);

   a = 12.34;
   a -= 56.78;
   printf("%f\n", a);

   a = 12.34;
   a *= 56.78;
   printf("%f\n", a);

   a = 12.34;
   a /= 56.78;
   printf("%f\n", a);

   printf("%f\n", +12.34);
   printf("%f\n", -12.34);

   a = 2;
   printf("%f\n", a);
   printf("%f\n", sin(2));

   return 0;
}
