// Simple virtual function example, based on http://www.cplusplus.com/doc/tutorial/polymorphism/
// compiled with:
// x86_64 -> g++ virtual-test.cpp -o virtual-test
// arm -> arm-linux-gnueabi-g++ virtual-test.cpp -o virtual-test-arm
#include <iostream>
using namespace std;

class Polygon {
  protected:
    int width, height;
  public:
    void set_values (int a, int b)
      { width=a; height=b; }
    virtual int area ()
      { return 0; }
    virtual int sides ()
      { return 0; }
};

class Rectangle: public Polygon {
  public:
    int area ()
      { return width * height; }
    int sides ()
      { return 4; }
};

class Triangle: public Polygon {
  public:
    int area ()
      { return (width * height / 2); }
    int sides ()
      { return 3; }
};

void printArea(Polygon* poly)
{
  cout << poly->area() << endl;
}

void printSides(Polygon* poly)
{
  cout << poly->sides() << endl;
}

int main () {
  Rectangle rect;
  Triangle trgl;
  Polygon poly;
  Polygon * ppoly1 = &rect;
  Polygon * ppoly2 = &trgl;
  Polygon * ppoly3 = &poly;
  ppoly1->set_values(4,5);
  ppoly2->set_values(4,5);
  ppoly3->set_values(4,5);
  printArea(ppoly1);
  printSides(ppoly1);
  printArea(ppoly2);
  printArea(ppoly3);
  return 0;
}